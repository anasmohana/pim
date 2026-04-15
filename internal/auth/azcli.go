package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// AzureContext represents the Azure CLI context
type AzureContext struct {
	TenantID         string
	SubscriptionID   string
	SubscriptionName string
	UserID           string
	AccessToken      string
	ExpiresOn        time.Time
}

// GetAzureContext retrieves the current Azure CLI context and token
func GetAzureContext() (*AzureContext, error) {
	// Get account information
	accountCmd := exec.Command("az", "account", "show", "--output", "json")
	accountOutput, err := accountCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure account info. Please run 'az login' first: %w", err)
	}

	var accountInfo struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		TenantID         string `json:"tenantId"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}

	if err := json.Unmarshal(accountOutput, &accountInfo); err != nil {
		return nil, fmt.Errorf("failed to parse account info: %w", err)
	}

	// Get access token for Azure AD Graph
	tokenCmd := exec.Command("az", "account", "get-access-token",
		"--resource", "https://graph.microsoft.com", "--output", "json")
	tokenOutput, err := tokenCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var tokenInfo struct {
		AccessToken string `json:"accessToken"`
		ExpiresOn   string `json:"expiresOn"`
	}

	if err := json.Unmarshal(tokenOutput, &tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to parse token info: %w", err)
	}

	// Parse expiration time
	expiresOn, err := time.Parse("2006-01-02 15:04:05.999999", tokenInfo.ExpiresOn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token expiration: %w", err)
	}

	return &AzureContext{
		TenantID:         accountInfo.TenantID,
		SubscriptionID:   accountInfo.ID,
		SubscriptionName: accountInfo.Name,
		UserID:           accountInfo.User.Name,
		AccessToken:      tokenInfo.AccessToken,
		ExpiresOn:        expiresOn,
	}, nil
}

// GetAzureResourceToken gets an access token for Azure Resource Manager
func GetAzureResourceToken() (string, error) {
	tokenCmd := exec.Command("az", "account", "get-access-token",
		"--resource", "https://management.azure.com", "--output", "json")
	tokenOutput, err := tokenCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get ARM access token: %w", err)
	}

	var tokenInfo struct {
		AccessToken string `json:"accessToken"`
	}

	if err := json.Unmarshal(tokenOutput, &tokenInfo); err != nil {
		return "", fmt.Errorf("failed to parse token info: %w", err)
	}

	return tokenInfo.AccessToken, nil
}

// GetPIMToken gets an access token specifically for the MS PIM API
func GetPIMToken() (string, error) {
	tokenCmd := exec.Command("az", "account", "get-access-token",
		"--resource", "https://api.azrbac.mspim.azure.com", "--output", "json")
	tokenOutput, err := tokenCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get PIM access token: %w", err)
	}

	var tokenInfo struct {
		AccessToken string `json:"accessToken"`
	}

	if err := json.Unmarshal(tokenOutput, &tokenInfo); err != nil {
		return "", fmt.Errorf("failed to parse token info: %w", err)
	}

	return tokenInfo.AccessToken, nil
}

// ReauthenticateWithClaims re-authenticates using claims challenge for MFA/ACRS
func ReauthenticateWithClaims(claimValue string) error {
	fmt.Println("\n🔐 MFA/ACRS authentication required. Opening browser...")

	var claimsB64 string
	if claimValue != "" {
		decoded, err := url.QueryUnescape(claimValue)
		if err != nil {
			decoded = claimValue
		}
		claimsB64 = base64.StdEncoding.EncodeToString([]byte(decoded))
	}

	var loginCmd *exec.Cmd
	if claimsB64 != "" {
		fmt.Println("Using ACRS claims challenge for authentication...")
		loginCmd = exec.Command("az", "login",
			"--scope", "https://api.azrbac.mspim.azure.com/.default",
			"--claims-challenge", claimsB64)
	} else {
		loginCmd = exec.Command("az", "login",
			"--scope", "https://api.azrbac.mspim.azure.com/.default")
	}

	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	if err := loginCmd.Run(); err != nil {
		if claimsB64 != "" && strings.Contains(err.Error(), "unrecognized arguments") {
			fmt.Println("Retrying without claims parameter...")
			loginCmd = exec.Command("az", "login",
				"--scope", "https://api.azrbac.mspim.azure.com/.default")
			loginCmd.Stdout = os.Stdout
			loginCmd.Stderr = os.Stderr
			if err := loginCmd.Run(); err != nil {
				return fmt.Errorf("authentication failed: %w", err)
			}
		} else {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	fmt.Println("\n✓ Authentication successful!")
	return nil
}

// SimpleReauthenticate performs a simple re-authentication
func SimpleReauthenticate() error {
	fmt.Println("\n🔐 Authentication required. Opening browser...")
	fmt.Println("Please complete the authentication...")

	loginCmd := exec.Command("az", "login")
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	if err := loginCmd.Run(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Println("✓ Authentication successful!")
	return nil
}
