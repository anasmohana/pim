package pim

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"pim-manager/pkg/models"
	"strings"
	"time"
)

// AzureResourcePIMClient handles Azure Resource PIM operations
type AzureResourcePIMClient struct {
	accessToken    string
	principalID    string
	subscriptionID string
}

// NewAzureResourcePIMClient creates a new Azure Resource PIM client
func NewAzureResourcePIMClient(accessToken, principalID, subscriptionID string) *AzureResourcePIMClient {
	return &AzureResourcePIMClient{
		accessToken:    accessToken,
		principalID:    principalID,
		subscriptionID: subscriptionID,
	}
}

// ListEligibleRoles lists all eligible Azure resource roles
func (c *AzureResourcePIMClient) ListEligibleRoles() ([]models.RoleAssignment, error) {
	scope := fmt.Sprintf("subscriptions/%s", c.subscriptionID)
	url := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()", scope)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				Scope            string `json:"scope"`
				StartDateTime    string `json:"startDateTime"`
				EndDateTime      string `json:"endDateTime"`
				Status           string `json:"status"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	roles := make([]models.RoleAssignment, 0)
	for _, item := range result.Value {
		// Get role name
		roleName, _ := c.getRoleName(item.Properties.RoleDefinitionID)

		startTime, _ := time.Parse(time.RFC3339, item.Properties.StartDateTime)
		endTime, _ := time.Parse(time.RFC3339, item.Properties.EndDateTime)

		roles = append(roles, models.RoleAssignment{
			ID:               item.ID,
			RoleDefinitionID: item.Properties.RoleDefinitionID,
			RoleName:         roleName,
			PrincipalID:      item.Properties.PrincipalID,
			Scope:            item.Properties.Scope,
			Status:           "Eligible",
			Type:             models.RoleTypeAzureResource,
			StartDateTime:    startTime,
			EndDateTime:      endTime,
			IsEligible:       true,
		})
	}

	return roles, nil
}

// ListActiveRoles lists all active Azure resource role assignments
func (c *AzureResourcePIMClient) ListActiveRoles() ([]models.RoleAssignment, error) {
	scope := fmt.Sprintf("subscriptions/%s", c.subscriptionID)
	url := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()", scope)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				Scope            string `json:"scope"`
				StartDateTime    string `json:"startDateTime"`
				EndDateTime      string `json:"endDateTime"`
				Status           string `json:"status"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	roles := make([]models.RoleAssignment, 0)
	for _, item := range result.Value {
		roleName, _ := c.getRoleName(item.Properties.RoleDefinitionID)

		startTime, _ := time.Parse(time.RFC3339, item.Properties.StartDateTime)
		endTime, _ := time.Parse(time.RFC3339, item.Properties.EndDateTime)

		roles = append(roles, models.RoleAssignment{
			ID:               item.ID,
			RoleDefinitionID: item.Properties.RoleDefinitionID,
			RoleName:         roleName,
			PrincipalID:      item.Properties.PrincipalID,
			Scope:            item.Properties.Scope,
			Status:           "Active",
			Type:             models.RoleTypeAzureResource,
			StartDateTime:    startTime,
			EndDateTime:      endTime,
			IsEligible:       false,
		})
	}

	return roles, nil
}

// ActivateRole activates an eligible Azure resource role
func (c *AzureResourcePIMClient) ActivateRole(scope string, req models.ActivationRequest) error {
	requestID := generateUUID()
	url := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/%s?api-version=2020-10-01",
		scope, requestID)

	payload := map[string]interface{}{
		"properties": map[string]interface{}{
			"principalId":      c.principalID,
			"roleDefinitionId": req.RoleDefinitionID,
			"requestType":      "SelfActivate",
			"justification":    req.Justification,
			"scheduleInfo": map[string]interface{}{
				"startDateTime": time.Now().UTC().Format(time.RFC3339),
				"expiration": map[string]interface{}{
					"type":     "AfterDuration",
					"duration": req.Duration,
				},
			},
		},
	}

	if req.TicketNumber != "" {
		payload["properties"].(map[string]interface{})["ticketInfo"] = map[string]interface{}{
			"ticketNumber": req.TicketNumber,
			"ticketSystem": req.TicketSystem,
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("activation failed with status %d", resp.StatusCode)
	}

	return nil
}

// DeactivateRole deactivates an active Azure resource role
func (c *AzureResourcePIMClient) DeactivateRole(scope string, roleDefinitionID string) error {
	requestID := generateUUID()
	url := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/%s?api-version=2020-10-01",
		scope, requestID)

	payload := map[string]interface{}{
		"properties": map[string]interface{}{
			"principalId":      c.principalID,
			"roleDefinitionId": roleDefinitionID,
			"requestType":      "SelfDeactivate",
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("deactivation failed with status %d", resp.StatusCode)
	}

	return nil
}

// getRoleName retrieves the display name for a role definition ID
func (c *AzureResourcePIMClient) getRoleName(roleDefinitionID string) (string, error) {
	// Common role ID mappings for known Azure built-in roles
	commonRoles := map[string]string{
		"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
		"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
		"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
		"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
		"b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b": "Azure Kubernetes Service Cluster User Role",
		"00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
		"800e0198-3cf4-4ab0-851f-2509efcfe4c1": "KeyVault",
	}

	// Extract just the GUID from the role definition ID
	parts := strings.Split(roleDefinitionID, "/")
	roleGUID := parts[len(parts)-1]

	// Check if it's a known common role
	if roleName, exists := commonRoles[roleGUID]; exists {
		return roleName, nil
	}

	// Try to fetch from API
	url := fmt.Sprintf("https://management.azure.com%s?api-version=2022-04-01", roleDefinitionID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return roleGUID, nil // Return GUID as fallback
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return roleGUID, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return roleGUID, nil
	}

	var result struct {
		Properties struct {
			RoleName string `json:"roleName"`
		} `json:"properties"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return roleGUID, nil
	}

	if result.Properties.RoleName == "" {
		return roleGUID, nil
	}

	return result.Properties.RoleName, nil
}

// generateUUID generates a UUID v4 for Azure requests
func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp if random generation fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GetRolePolicy retrieves the PIM policy for a role to get max duration
func (c *AzureResourcePIMClient) GetRolePolicy(scope string, roleDefinitionID string) (int, error) {
	// Get the policy assignment for this role
	filter := fmt.Sprintf("roleDefinitionId eq '%s'", roleDefinitionID)
	url := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01&$filter=%s",
		scope, filter)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 5, err // Default to 5 hours on error
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 5, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 5, nil // Default to 5 hours if we can't fetch policy
	}

	var result struct {
		Value []struct {
			Properties struct {
				PolicyID string `json:"policyId"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 5, err
	}

	if len(result.Value) == 0 {
		return 5, nil // No policy found, default to 5 hours
	}

	// Get the actual policy details
	policyID := result.Value[0].Properties.PolicyID
	policyURL := fmt.Sprintf("https://management.azure.com%s?api-version=2020-10-01", policyID)

	policyReq, err := http.NewRequest("GET", policyURL, nil)
	if err != nil {
		return 5, err
	}

	policyReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	policyReq.Header.Set("Content-Type", "application/json")

	policyResp, err := client.Do(policyReq)
	if err != nil {
		return 5, err
	}
	defer policyResp.Body.Close()

	if policyResp.StatusCode != http.StatusOK {
		return 5, nil
	}

	var policyResult struct {
		Properties struct {
			Rules []struct {
				ID             string `json:"id"`
				RuleType       string `json:"ruleType"`
				MaximumDuration string `json:"maximumDuration"`
			} `json:"rules"`
		} `json:"properties"`
	}

	if err := json.NewDecoder(policyResp.Body).Decode(&policyResult); err != nil {
		return 5, err
	}

	// Find the expiration rule
	for _, rule := range policyResult.Properties.Rules {
		if rule.RuleType == "RoleManagementPolicyExpirationRule" && rule.ID == "Expiration_EndUser_Assignment" {
			// Parse duration like "PT5H" to hours
			duration := rule.MaximumDuration
			if strings.HasPrefix(duration, "PT") && strings.HasSuffix(duration, "H") {
				durationStr := strings.TrimPrefix(duration, "PT")
				durationStr = strings.TrimSuffix(durationStr, "H")
				var hours int
				fmt.Sscanf(durationStr, "%d", &hours)
				return hours, nil
			}
		}
	}

	return 5, nil // Default fallback
}
