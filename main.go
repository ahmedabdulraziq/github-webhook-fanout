package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
)

// ArgoCDConfig represents configuration for an ArgoCD instance
type ArgoCDConfig struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	AppName  string `json:"appName"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Token is kept for backward compatibility but basic auth is preferred
	Token string `json:"token,omitempty"`
}

// Config holds the application configuration
type Config struct {
	Port          string         `json:"port"`
	GitHubSecret  string         `json:"githubSecret"`
	ArgoCDConfigs []ArgoCDConfig `json:"argocdConfigs"`
}

// GitHubWebhookPayload represents the GitHub webhook payload
type GitHubWebhookPayload struct {
	Ref        string `json:"ref"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"commits"`
}

var config Config

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load configuration
	loadConfig()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
	})

	// Add middleware
	app.Use(logger.New())
	app.Use(recover.New())

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// GitHub webhook endpoint
	app.Post("/webhook", handleGitHubWebhook)

	// Start server
	port := config.Port
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting GitHub webhook fanout server on port %s", port)
	log.Printf("Configured %d ArgoCD instances", len(config.ArgoCDConfigs))

	if err := app.Listen(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func loadConfig() {
	config = Config{
		Port:         getEnv("PORT", "8080"),
		GitHubSecret: getEnv("GITHUB_SECRET", ""),
	}

	// Load ArgoCD configurations from environment variables
	// Format: ARGOCD_CONFIGS='[{"name":"prod","url":"https://argocd.example.com","token":"token","appName":"my-app"}]'
	argocdConfigsJSON := getEnv("ARGOCD_CONFIGS", "[]")

	var argocdConfigs []ArgoCDConfig
	if err := json.Unmarshal([]byte(argocdConfigsJSON), &argocdConfigs); err != nil {
		log.Printf("Warning: Failed to parse ARGOCD_CONFIGS: %v", err)
		argocdConfigs = []ArgoCDConfig{}
	}

	config.ArgoCDConfigs = argocdConfigs
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func handleGitHubWebhook(c *fiber.Ctx) error {
	// Verify GitHub webhook signature
	if !verifyGitHubSignature(c) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid signature"})
	}

	// Parse webhook payload
	var payload GitHubWebhookPayload
	if err := c.BodyParser(&payload); err != nil {
		log.Printf("Failed to parse webhook payload: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON payload"})
	}

	// Log webhook details
	log.Printf("Received webhook for repository: %s, ref: %s, commits: %d",
		payload.Repository.FullName, payload.Ref, len(payload.Commits))

	// Trigger ArgoCD deployments
	results := triggerArgoCDDeployments()

	// Return results
	return c.JSON(fiber.Map{
		"message": "Webhook processed successfully",
		"results": results,
	})
}

func verifyGitHubSignature(c *fiber.Ctx) bool {
	if config.GitHubSecret == "" {
		log.Println("Warning: No GitHub secret configured, skipping signature verification")
		return true
	}

	signature := c.Get("X-Hub-Signature-256")
	if signature == "" {
		return false
	}

	// Get the request body
	body := c.Body()
	if len(body) == 0 {
		log.Printf("Empty request body")
		return false
	}

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(config.GitHubSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)

	// Compare signatures
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func triggerArgoCDDeployments() []map[string]interface{} {
	var results []map[string]interface{}

	for _, argocdConfig := range config.ArgoCDConfigs {
		result := map[string]interface{}{
			"name":    argocdConfig.Name,
			"url":     argocdConfig.URL,
			"success": false,
			"error":   nil,
		}

		// Trigger ArgoCD sync
		if err := triggerArgoCDSync(argocdConfig); err != nil {
			log.Printf("Failed to trigger ArgoCD sync for %s: %v", argocdConfig.Name, err)
			result["error"] = err.Error()
		} else {
			log.Printf("Successfully triggered ArgoCD sync for %s", argocdConfig.Name)
			result["success"] = true
		}

		results = append(results, result)
	}

	return results
}

func triggerArgoCDSync(argocdConfig ArgoCDConfig) error {
	// Prepare the sync request
	syncRequest := map[string]interface{}{
		"prune":  true,
		"dryRun": false,
		"strategy": map[string]interface{}{
			"apply": map[string]interface{}{
				"force": false,
			},
		},
	}

	jsonData, err := json.Marshal(syncRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal sync request: %v", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/applications/%s/sync", argocdConfig.URL, argocdConfig.AppName)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Set authentication - prioritize basic auth over token
	if argocdConfig.Username != "" && argocdConfig.Password != "" {
		req.SetBasicAuth(argocdConfig.Username, argocdConfig.Password)
	} else if argocdConfig.Token != "" {
		req.Header.Set("Authorization", "Bearer "+argocdConfig.Token)
	}

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ArgoCD API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
