package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// Microsoft public client ID for device code flow
	publicClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" // Azure CLI client ID
	authorityURL   = "https://login.microsoftonline.com/organizations"
	graphResource  = "https://graph.microsoft.com"
)

// DeviceCodeResponse represents the device code flow initial response
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// GetTokenViaDeviceCode performs device code flow to get a token with PIM scopes
func GetTokenViaDeviceCode(tenantID string) (string, error) {
	// Request device code
	deviceCodeURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenantID)

	// Request specific PIM scopes
	scopes := "https://graph.microsoft.com/RoleManagement.Read.Directory https://graph.microsoft.com/RoleManagement.ReadWrite.Directory offline_access"

	reqBody := fmt.Sprintf("client_id=%s&scope=%s", publicClientID, scopes)

	resp, err := http.Post(deviceCodeURL, "application/x-www-form-urlencoded", bytes.NewBufferString(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("device code request failed: %s", string(body))
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return "", fmt.Errorf("failed to decode device code response: %w", err)
	}

	// Display user instructions
	fmt.Println("\n" + deviceCode.Message)
	fmt.Printf("\nWaiting for authentication...\n")

	// Poll for token
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	interval := time.Duration(deviceCode.Interval) * time.Second
	timeout := time.After(time.Duration(deviceCode.ExpiresIn) * time.Second)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("device code authentication timed out")
		case <-ticker.C:
			tokenReqBody := fmt.Sprintf("grant_type=device_code&client_id=%s&device_code=%s",
				publicClientID, deviceCode.DeviceCode)

			tokenResp, err := http.Post(tokenURL, "application/x-www-form-urlencoded",
				bytes.NewBufferString(tokenReqBody))
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(tokenResp.Body)
			tokenResp.Body.Close()

			if tokenResp.StatusCode == http.StatusOK {
				var token TokenResponse
				if err := json.Unmarshal(body, &token); err != nil {
					return "", fmt.Errorf("failed to decode token: %w", err)
				}
				fmt.Println("✓ Authentication successful!")
				return token.AccessToken, nil
			}

			// Check if still pending
			var errResp struct {
				Error string `json:"error"`
			}
			json.Unmarshal(body, &errResp)
			if errResp.Error != "authorization_pending" {
				return "", fmt.Errorf("authentication failed: %s", errResp.Error)
			}
		}
	}
}
