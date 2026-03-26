package auth

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// AzureContext represents the Azure CLI context
type AzureContext struct {
	TenantID       string
	SubscriptionID string
	SubscriptionName string
	UserID         string
	AccessToken    string
	ExpiresOn      time.Time
}

// Subscription represents an Azure subscription
type Subscription struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TenantID string `json:"tenantId"`
	State    string `json:"state"`
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

// ValidateContext checks if the Azure context is valid and prompts user if needed
func ValidateContext(ctx *AzureContext) error {
	fmt.Println("Current Azure Context:")
	fmt.Printf("  Tenant ID:        %s\n", ctx.TenantID)
	fmt.Printf("  User:             %s\n", ctx.UserID)
	fmt.Printf("  Token Expires:    %s\n", ctx.ExpiresOn.Format("2006-01-02 15:04:05"))

	if time.Now().After(ctx.ExpiresOn) {
		return fmt.Errorf("access token has expired. Please run 'az login' again")
	}

	if time.Until(ctx.ExpiresOn) < 5*time.Minute {
		fmt.Println("\nWarning: Access token expires soon. Consider running 'az login' to refresh.")
	}

	fmt.Println("\nNote: This tool will check PIM roles across ALL your subscriptions.")

	return nil
}

// GetAllSubscriptions retrieves all Azure subscriptions the user has access to
func GetAllSubscriptions() ([]Subscription, error) {
	cmd := exec.Command("az", "account", "list", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list subscriptions: %w", err)
	}

	var subscriptions []Subscription
	if err := json.Unmarshal(output, &subscriptions); err != nil {
		return nil, fmt.Errorf("failed to parse subscriptions: %w", err)
	}

	// Filter only enabled subscriptions
	enabled := make([]Subscription, 0)
	for _, sub := range subscriptions {
		if sub.State == "Enabled" {
			enabled = append(enabled, sub)
		}
	}

	return enabled, nil
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
	fmt.Println("IMPORTANT: After completing the browser login, you MUST approve the")
	fmt.Println("           request in your Azure Authenticator app (check your phone)!")
	fmt.Println()

	// Clear existing tokens to force fresh authentication (like bash script does)
	clearCmd := exec.Command("az", "account", "clear")
	clearCmd.Run() // Ignore errors

	// Simple login - let Azure CLI handle the authentication naturally
	loginCmd := exec.Command("az", "login")
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	if err := loginCmd.Run(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Println("\n✓ Browser login successful!")
	fmt.Println()
	fmt.Print("Please approve the request in your Azure Authenticator app now...")
	fmt.Println()
	fmt.Print("Press Enter after you have approved in the authenticator app: ")

	// Wait for user to confirm they've approved in authenticator
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')

	fmt.Println("✓ Proceeding with activation...")

	return nil
}

// SimpleReauthenticate performs a simple re-authentication
func SimpleReauthenticate() error {
	fmt.Println("\n🔐 Authentication required. Opening browser...")
	fmt.Println("Please complete the authentication...")

	// Clear existing tokens first to force fresh login
	clearCmd := exec.Command("az", "account", "clear")
	clearCmd.Run() // Ignore errors

	// Simple login without scope - let az rest handle scope negotiation
	loginCmd := exec.Command("az", "login")
	loginCmd.Stdout = os.Stdout
	loginCmd.Stderr = os.Stderr

	if err := loginCmd.Run(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Println("✓ Authentication successful!")

	return nil
}
