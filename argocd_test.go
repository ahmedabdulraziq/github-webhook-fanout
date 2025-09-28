package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTriggerArgoCDSync(t *testing.T) {
	// Create a mock ArgoCD server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle session request
		if r.URL.Path == "/api/v1/session" {
			// Verify session request
			var sessionRequest map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&sessionRequest)
			require.NoError(t, err)

			assert.Equal(t, "admin", sessionRequest["username"])
			assert.Equal(t, "test-password", sessionRequest["password"])

			// Return session response with token
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "mock-session-token"}`))
			return
		}

		// Handle sync request
		if r.URL.Path == "/api/v1/applications/test-app/sync" {
			// Verify the request method and path
			assert.Equal(t, "POST", r.Method)

			// Verify headers
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer mock-session-token", r.Header.Get("Authorization"))

			// Verify request body
			var syncRequest map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&syncRequest)
			require.NoError(t, err)

			assert.Equal(t, true, syncRequest["prune"])
			assert.Equal(t, false, syncRequest["dryRun"])

			// Check strategy structure
			strategy, ok := syncRequest["strategy"].(map[string]interface{})
			assert.True(t, ok, "Strategy should be an object")
			apply, ok := strategy["apply"].(map[string]interface{})
			assert.True(t, ok, "Strategy should have apply field")
			assert.Equal(t, false, apply["force"])

			// Return success response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))
			return
		}

		// Unknown endpoint
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer mockServer.Close()

	// Test configuration
	argocdConfig := ArgoCDConfig{
		Name:     "test",
		URL:      mockServer.URL,
		Username: "admin",
		Password: "test-password",
		AppName:  "test-app",
	}

	// Test successful sync
	err := triggerArgoCDSync(argocdConfig)
	assert.NoError(t, err)
}

func TestTriggerArgoCDSyncWithUsernamePassword(t *testing.T) {
	// Create a mock ArgoCD server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle session request
		if r.URL.Path == "/api/v1/session" {
			// Verify session request
			var sessionRequest map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&sessionRequest)
			require.NoError(t, err)

			assert.Equal(t, "admin", sessionRequest["username"])
			assert.Equal(t, "password", sessionRequest["password"])

			// Return session response with token
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token": "mock-session-token"}`))
			return
		}

		// Handle sync request
		if r.URL.Path == "/api/v1/applications/test-app/sync" {
			// Verify Bearer token auth
			authHeader := r.Header.Get("Authorization")
			assert.Equal(t, "Bearer mock-session-token", authHeader)

			// Return success response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))
			return
		}

		// Unknown endpoint
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer mockServer.Close()

	// Test configuration with username/password
	argocdConfig := ArgoCDConfig{
		Name:     "test",
		URL:      mockServer.URL,
		Username: "admin",
		Password: "password",
		AppName:  "test-app",
	}

	// Test successful sync
	err := triggerArgoCDSync(argocdConfig)
	assert.NoError(t, err)
}

func TestTriggerArgoCDSyncWithError(t *testing.T) {
	// Create a mock ArgoCD server that returns an error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error"}`))
	}))
	defer mockServer.Close()

	// Test configuration
	argocdConfig := ArgoCDConfig{
		Name:     "test",
		URL:      mockServer.URL,
		Username: "admin",
		Password: "test-password",
		AppName:  "test-app",
	}

	// Test error handling
	err := triggerArgoCDSync(argocdConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ArgoCD API returned status 500")
}

func TestTriggerArgoCDSyncWithNetworkError(t *testing.T) {
	// Test with invalid URL to simulate network error
	argocdConfig := ArgoCDConfig{
		Name:    "test",
		URL:     "http://invalid-url-that-does-not-exist",
		Token:   "test-token",
		AppName: "test-app",
	}

	// Test network error handling
	err := triggerArgoCDSync(argocdConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to make request")
}

func TestTriggerArgoCDDeploymentsMultiple(t *testing.T) {
	// Create multiple mock servers
	mockServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer mockServer1.Close()

	mockServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer mockServer2.Close()

	// Set up configuration with multiple ArgoCD instances
	config.ArgoCDConfigs = []ArgoCDConfig{
		{
			Name:    "prod",
			URL:     mockServer1.URL,
			Token:   "prod-token",
			AppName: "prod-app",
		},
		{
			Name:    "staging",
			URL:     mockServer2.URL,
			Token:   "staging-token",
			AppName: "staging-app",
		},
	}

	// Test multiple deployments
	results := triggerArgoCDDeployments()

	assert.Len(t, results, 2)

	// Check first result
	assert.Equal(t, "prod", results[0]["name"])
	assert.Equal(t, mockServer1.URL, results[0]["url"])
	assert.Equal(t, true, results[0]["success"])
	assert.Nil(t, results[0]["error"])

	// Check second result
	assert.Equal(t, "staging", results[1]["name"])
	assert.Equal(t, mockServer2.URL, results[1]["url"])
	assert.Equal(t, true, results[1]["success"])
	assert.Nil(t, results[1]["error"])
}
