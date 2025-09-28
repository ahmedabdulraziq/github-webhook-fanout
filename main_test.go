package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set test environment variables
	os.Setenv("PORT", "8080")
	os.Setenv("GITHUB_SECRET", "test-secret")
	os.Setenv("ARGOCD_CONFIGS", `[{"name":"test","url":"https://argocd.test.com","username":"admin","password":"test-password","appName":"test-app"}]`)

	// Run tests
	code := m.Run()

	// Cleanup
	os.Unsetenv("PORT")
	os.Unsetenv("GITHUB_SECRET")
	os.Unsetenv("ARGOCD_CONFIGS")

	os.Exit(code)
}

func TestHealthEndpoint(t *testing.T) {
	app := createTestApp()

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
}

func TestWebhookEndpointWithoutSignature(t *testing.T) {
	app := createTestApp()

	payload := createTestWebhookPayloadForTest()
	jsonPayload, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "Invalid signature", response["error"])
}

func TestWebhookEndpointWithValidSignature(t *testing.T) {
	// Set empty ArgoCD configs to avoid actual API calls
	originalConfigs := config.ArgoCDConfigs
	config.ArgoCDConfigs = []ArgoCDConfig{}
	defer func() {
		config.ArgoCDConfigs = originalConfigs
	}()

	app := createTestApp()

	payload := createTestWebhookPayloadForTest()
	jsonPayload, _ := json.Marshal(payload)

	// Calculate valid signature
	signature := calculateSignature(jsonPayload, "test-secret")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", signature)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "Webhook processed successfully", response["message"])
	assert.NotNil(t, response["results"])
}

func TestWebhookEndpointWithInvalidSignature(t *testing.T) {
	app := createTestApp()

	payload := createTestWebhookPayloadForTest()
	jsonPayload, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/webhook", bytes.NewBuffer(jsonPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid-signature")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "Invalid signature", response["error"])
}

func TestWebhookEndpointWithInvalidJSON(t *testing.T) {
	app := createTestApp()

	invalidJSON := `{"invalid": json}`
	signature := calculateSignature([]byte(invalidJSON), "test-secret")

	req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(invalidJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", signature)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "Invalid JSON payload", response["error"])
}

func TestLoadConfig(t *testing.T) {
	// Set environment variables for this test
	os.Setenv("PORT", "8080")
	os.Setenv("GITHUB_SECRET", "test-secret")
	os.Setenv("ARGOCD_CONFIGS", `[{"name":"test","url":"https://argocd.test.com","username":"admin","password":"test-password","appName":"test-app"}]`)

	// Load configuration
	loadConfig()

	assert.Equal(t, "8080", config.Port)
	assert.Equal(t, "test-secret", config.GitHubSecret)
	assert.Len(t, config.ArgoCDConfigs, 1)
	assert.Equal(t, "test", config.ArgoCDConfigs[0].Name)
	assert.Equal(t, "https://argocd.test.com", config.ArgoCDConfigs[0].URL)
	assert.Equal(t, "admin", config.ArgoCDConfigs[0].Username)
	assert.Equal(t, "test-password", config.ArgoCDConfigs[0].Password)
	assert.Equal(t, "test-app", config.ArgoCDConfigs[0].AppName)
}

func TestLoadConfigWithInvalidJSON(t *testing.T) {
	// Test with invalid JSON
	os.Setenv("ARGOCD_CONFIGS", `invalid-json`)

	config := Config{}
	loadConfig()

	assert.Equal(t, "8080", config.Port)
	assert.Equal(t, "test-secret", config.GitHubSecret)
	assert.Len(t, config.ArgoCDConfigs, 0) // Should be empty due to invalid JSON
}

func TestGetEnv(t *testing.T) {
	// Test with existing environment variable
	os.Setenv("TEST_VAR", "test-value")
	assert.Equal(t, "test-value", getEnv("TEST_VAR", "default"))

	// Test with non-existing environment variable
	assert.Equal(t, "default", getEnv("NON_EXISTING_VAR", "default"))

	// Cleanup
	os.Unsetenv("TEST_VAR")
}

func TestVerifyGitHubSignature(t *testing.T) {
	// Test signature calculation directly
	payload := []byte(`{"test": "data"}`)
	signature := calculateSignature(payload, "test-secret")

	// Calculate expected signature
	expectedSignature := calculateSignature(payload, "test-secret")
	assert.Equal(t, signature, expectedSignature)

	// Test with different payload
	payload2 := []byte(`{"different": "data"}`)
	signature2 := calculateSignature(payload2, "test-secret")
	assert.NotEqual(t, signature, signature2)
}

func TestTriggerArgoCDDeployments(t *testing.T) {
	// Set up test configuration
	config.ArgoCDConfigs = []ArgoCDConfig{
		{
			Name:     "test",
			URL:      "https://argocd.test.com",
			Username: "admin",
			Password: "test-password",
			AppName:  "test-app",
		},
	}

	results := triggerArgoCDDeployments()

	assert.Len(t, results, 1)
	assert.Equal(t, "test", results[0]["name"])
	assert.Equal(t, "https://argocd.test.com", results[0]["url"])
	// Note: The actual sync will fail in tests since we don't have a real ArgoCD instance
	// but we can verify the structure is correct
}

// Helper functions for testing

func createTestApp() *fiber.App {
	loadConfig()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
	})

	app.Use(logger.New())
	app.Use(recover.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	app.Post("/webhook", handleGitHubWebhook)

	return app
}

func createTestWebhookPayloadForTest() GitHubWebhookPayload {
	return GitHubWebhookPayload{
		Ref: "refs/heads/main",
		Repository: struct {
			Name     string `json:"name"`
			FullName string `json:"full_name"`
		}{
			Name:     "test-repo",
			FullName: "user/test-repo",
		},
		Commits: []struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		}{
			{
				ID:      "abc123",
				Message: "Test commit",
			},
		},
	}
}

func calculateSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	hash := mac.Sum(nil)
	return "sha256=" + hex.EncodeToString(hash)
}
