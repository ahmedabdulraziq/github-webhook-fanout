package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignatureCalculation(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		secret   string
		expected string
	}{
		{
			name:     "simple payload",
			payload:  `{"test": "data"}`,
			secret:   "test-secret",
			expected: "sha256=" + hex.EncodeToString(hmac.New(sha256.New, []byte("test-secret")).Sum([]byte(`{"test": "data"}`))),
		},
		{
			name:     "empty payload",
			payload:  "",
			secret:   "test-secret",
			expected: "sha256=" + hex.EncodeToString(hmac.New(sha256.New, []byte("test-secret")).Sum([]byte(""))),
		},
		{
			name:     "complex payload",
			payload:  `{"repository":{"name":"test","full_name":"user/test"},"ref":"refs/heads/main","commits":[{"id":"abc123","message":"test"}]}`,
			secret:   "complex-secret",
			expected: "sha256=" + hex.EncodeToString(hmac.New(sha256.New, []byte("complex-secret")).Sum([]byte(`{"repository":{"name":"test","full_name":"user/test"},"ref":"refs/heads/main","commits":[{"id":"abc123","message":"test"}]}`))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate signature using our helper function
			actual := calculateTestSignature([]byte(tt.payload), tt.secret)

			// Calculate expected signature manually
			mac := hmac.New(sha256.New, []byte(tt.secret))
			mac.Write([]byte(tt.payload))
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			assert.Equal(t, expected, actual)
		})
	}
}

func TestSignatureVerification(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		secret     string
		signature  string
		shouldPass bool
	}{
		{
			name:       "valid signature",
			payload:    `{"test": "data"}`,
			secret:     "test-secret",
			signature:  "", // Will be calculated
			shouldPass: true,
		},
		{
			name:       "invalid signature",
			payload:    `{"test": "data"}`,
			secret:     "test-secret",
			signature:  "sha256=invalid-signature",
			shouldPass: false,
		},
		{
			name:       "wrong secret",
			payload:    `{"test": "data"}`,
			secret:     "test-secret",
			signature:  "", // Will be calculated with wrong secret
			shouldPass: false,
		},
		{
			name:       "empty signature",
			payload:    `{"test": "data"}`,
			secret:     "test-secret",
			signature:  "",
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate signature if needed
			if tt.signature == "" && tt.shouldPass {
				tt.signature = calculateTestSignature([]byte(tt.payload), tt.secret)
			} else if tt.signature == "" && !tt.shouldPass {
				// Use wrong secret to generate invalid signature
				tt.signature = calculateTestSignature([]byte(tt.payload), "wrong-secret")
			}

			// Test signature verification
			payloadBytes := []byte(tt.payload)
			secretBytes := []byte(tt.secret)
			signatureBytes := []byte(tt.signature)

			// Calculate expected signature
			mac := hmac.New(sha256.New, secretBytes)
			mac.Write(payloadBytes)
			expectedMAC := mac.Sum(nil)
			expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)

			// Compare signatures
			valid := hmac.Equal(signatureBytes, []byte(expectedSignature))

			if tt.shouldPass {
				assert.True(t, valid, "Signature should be valid")
			} else {
				assert.False(t, valid, "Signature should be invalid")
			}
		})
	}
}

func TestSignatureWithDifferentSecrets(t *testing.T) {
	payload := `{"test": "data"}`

	// Test with different secrets
	secrets := []string{"secret1", "secret2", "very-long-secret-key", "short"}

	for _, secret1 := range secrets {
		for _, secret2 := range secrets {
			sig1 := calculateTestSignature([]byte(payload), secret1)
			sig2 := calculateTestSignature([]byte(payload), secret2)

			if secret1 == secret2 {
				assert.Equal(t, sig1, sig2, "Signatures should be equal for same secret")
			} else {
				assert.NotEqual(t, sig1, sig2, "Signatures should be different for different secrets")
			}
		}
	}
}

func TestSignatureWithDifferentPayloads(t *testing.T) {
	secret := "test-secret"
	payloads := []string{
		`{"test": "data"}`,
		`{"test": "data2"}`,
		`{"test": "data","extra": "field"}`,
		`{"different": "structure"}`,
		``,
	}

	signatures := make([]string, len(payloads))

	// Calculate signatures for all payloads
	for i, payload := range payloads {
		signatures[i] = calculateTestSignature([]byte(payload), secret)
	}

	// All signatures should be different
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			assert.NotEqual(t, signatures[i], signatures[j],
				"Signatures should be different for different payloads")
		}
	}
}

func TestSignatureFormat(t *testing.T) {
	payload := `{"test": "data"}`
	secret := "test-secret"

	signature := calculateTestSignature([]byte(payload), secret)

	// Signature should start with "sha256="
	assert.True(t, len(signature) > 7, "Signature should be longer than 'sha256='")
	assert.Equal(t, "sha256=", signature[:7], "Signature should start with 'sha256='")

	// The rest should be valid hex
	hexPart := signature[7:]
	assert.True(t, len(hexPart) > 0, "Hex part should not be empty")

	// Try to decode as hex
	_, err := hex.DecodeString(hexPart)
	assert.NoError(t, err, "Hex part should be valid hexadecimal")
}
