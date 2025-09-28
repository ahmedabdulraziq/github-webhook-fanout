package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

// Test utilities and helper functions

// createTestConfig creates a test configuration
func createTestConfig() Config {
	return Config{
		Port:         "8080",
		GitHubSecret: "test-secret",
		ArgoCDConfigs: []ArgoCDConfig{
			{
				Name:     "test",
				URL:      "https://argocd.test.com",
				Username: "admin",
				Password: "test-password",
				AppName:  "test-app",
			},
		},
	}
}

// createTestWebhookPayload creates a test webhook payload
func createTestWebhookPayload() GitHubWebhookPayload {
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

// calculateTestSignature calculates HMAC signature for testing
func calculateTestSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	hash := mac.Sum(nil)
	return "sha256=" + hex.EncodeToString(hash)
}

// setTestEnv sets environment variables for testing
func setTestEnv() {
	os.Setenv("PORT", "8080")
	os.Setenv("GITHUB_SECRET", "test-secret")
	os.Setenv("ARGOCD_CONFIGS", `[{"name":"test","url":"https://argocd.test.com","token":"test-token","appName":"test-app"}]`)
}

// unsetTestEnv cleans up test environment variables
func unsetTestEnv() {
	os.Unsetenv("PORT")
	os.Unsetenv("GITHUB_SECRET")
	os.Unsetenv("ARGOCD_CONFIGS")
}

// createTestArgoCDConfig creates a test ArgoCD configuration
func createTestArgoCDConfig() ArgoCDConfig {
	return ArgoCDConfig{
		Name:     "test",
		URL:      "https://argocd.test.com",
		Username: "admin",
		Password: "test-password",
		AppName:  "test-app",
	}
}

// createTestArgoCDConfigWithAuth creates a test ArgoCD configuration with username/password
func createTestArgoCDConfigWithAuth() ArgoCDConfig {
	return ArgoCDConfig{
		Name:     "test",
		URL:      "https://argocd.test.com",
		Username: "admin",
		Password: "password",
		AppName:  "test-app",
	}
}

// validateJSON validates that a string is valid JSON
func validateJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}

// createTestSyncRequest creates a test sync request payload
func createTestSyncRequest() map[string]interface{} {
	return map[string]interface{}{
		"prune":    true,
		"dryRun":   false,
		"strategy": "apply",
	}
}
