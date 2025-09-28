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

	// Log ArgoCD configuration (without passwords)
	log.Printf("Configured ArgoCD instances: %d", len(config.ArgoCDConfigs))
	for _, cfg := range config.ArgoCDConfigs {
		log.Printf("ArgoCD instance: %s at %s (app: %s)", cfg.Name, cfg.URL, cfg.AppName)
	}

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
	// First, try to get a session token if using basic auth
	var authToken string
	var err error

	if argocdConfig.Username != "" && argocdConfig.Password != "" {
		authToken, err = getArgoCDSessionToken(argocdConfig)
		if err != nil {
			log.Printf("Failed to get session token for %s, falling back to basic auth: %v", argocdConfig.Name, err)
			// Continue with basic auth as fallback
		}
	}

	// Check if application exists and get its details
	if err := checkApplicationExists(argocdConfig, authToken); err != nil {
		log.Printf("Application check failed for %s: %v", argocdConfig.Name, err)
		// Continue with sync attempt anyway
	}

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
	log.Printf("Making sync request to: %s for application: %s", url, argocdConfig.AppName)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Set authentication
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	} else if argocdConfig.Username != "" && argocdConfig.Password != "" {
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
		log.Printf("ArgoCD sync failed for %s: status %d, body: %s", argocdConfig.Name, resp.StatusCode, string(body))

		// Handle specific error cases
		if resp.StatusCode == 403 {
			return fmt.Errorf("permission denied: user '%s' does not have sync permissions for application '%s'. Please check ArgoCD RBAC settings", argocdConfig.Username, argocdConfig.AppName)
		}

		return fmt.Errorf("ArgoCD API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func getArgoCDSessionToken(argocdConfig ArgoCDConfig) (string, error) {
	log.Printf("Attempting to get session token for ArgoCD instance: %s", argocdConfig.Name)

	// Create session request
	sessionRequest := map[string]interface{}{
		"username": argocdConfig.Username,
		"password": argocdConfig.Password,
	}

	jsonData, err := json.Marshal(sessionRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session request: %v", err)
	}

	// Create session request
	url := fmt.Sprintf("%s/api/v1/session", argocdConfig.URL)
	log.Printf("Making session request to: %s", url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create session request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Make the session request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make session request: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Session request response status: %d", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Session request failed with body: %s", string(body))
		return "", fmt.Errorf("session request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get token
	var sessionResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&sessionResponse); err != nil {
		return "", fmt.Errorf("failed to decode session response: %v", err)
	}

	token, ok := sessionResponse["token"].(string)
	if !ok {
		log.Printf("Session response: %+v", sessionResponse)
		return "", fmt.Errorf("no token in session response")
	}

	log.Printf("Successfully obtained session token for ArgoCD instance: %s", argocdConfig.Name)
	return token, nil
}

func checkApplicationExists(argocdConfig ArgoCDConfig, authToken string) error {
	// Create request to get application details
	url := fmt.Sprintf("%s/api/v1/applications/%s", argocdConfig.URL, argocdConfig.AppName)
	log.Printf("Checking application existence: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create application check request: %v", err)
	}

	req.Header.Set("Accept", "application/json")

	// Set authentication
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	} else if argocdConfig.Username != "" && argocdConfig.Password != "" {
		req.SetBasicAuth(argocdConfig.Username, argocdConfig.Password)
	} else if argocdConfig.Token != "" {
		req.Header.Set("Authorization", "Bearer "+argocdConfig.Token)
	}

	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check application: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("Application check response status: %d", resp.StatusCode)

	if resp.StatusCode == 404 {
		return fmt.Errorf("application '%s' not found", argocdConfig.AppName)
	}

	if resp.StatusCode == 403 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("permission denied to access application '%s': %s", argocdConfig.AppName, string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("application check failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get application details
	var appResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&appResponse); err != nil {
		return fmt.Errorf("failed to decode application response: %v", err)
	}

	log.Printf("Application '%s' found: %+v", argocdConfig.AppName, appResponse)
	return nil
}
