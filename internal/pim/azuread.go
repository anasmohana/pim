package pim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"pim-manager/pkg/models"
	"time"
)

const (
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	betaBaseURL  = "https://graph.microsoft.com/beta"
)

// AzureADPIMClient handles Azure AD PIM operations
type AzureADPIMClient struct {
	accessToken string
	principalID string
}

// NewAzureADPIMClient creates a new Azure AD PIM client
func NewAzureADPIMClient(accessToken, principalID string) *AzureADPIMClient {
	return &AzureADPIMClient{
		accessToken: accessToken,
		principalID: principalID,
	}
}

// ListEligibleRoles lists all eligible Azure AD roles
func (c *AzureADPIMClient) ListEligibleRoles() ([]models.RoleAssignment, error) {
	// Fetch all and filter client-side due to Graph API filter limitations
	url := fmt.Sprintf("%s/roleManagement/directory/roleEligibilityScheduleInstances?$expand=roleDefinition", betaBaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value []struct {
			ID               string `json:"id"`
			RoleDefinitionID string `json:"roleDefinitionId"`
			PrincipalID      string `json:"principalId"`
			DirectoryScopeID string `json:"directoryScopeId"`
			StartDateTime    string `json:"startDateTime"`
			EndDateTime      string `json:"endDateTime"`
			RoleDefinition   struct {
				DisplayName string `json:"displayName"`
			} `json:"roleDefinition"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter client-side for the current principal
	roles := make([]models.RoleAssignment, 0)
	for _, item := range result.Value {
		// Only include roles for the current principal
		if item.PrincipalID != c.principalID {
			continue
		}

		startTime, _ := time.Parse(time.RFC3339, item.StartDateTime)
		endTime, _ := time.Parse(time.RFC3339, item.EndDateTime)

		roles = append(roles, models.RoleAssignment{
			ID:               item.ID,
			RoleDefinitionID: item.RoleDefinitionID,
			RoleName:         item.RoleDefinition.DisplayName,
			PrincipalID:      item.PrincipalID,
			Scope:            item.DirectoryScopeID,
			Status:           "Eligible",
			Type:             models.RoleTypeAzureAD,
			StartDateTime:    startTime,
			EndDateTime:      endTime,
			IsEligible:       true,
		})
	}

	return roles, nil
}

// ListActiveRoles lists all active Azure AD role assignments
func (c *AzureADPIMClient) ListActiveRoles() ([]models.RoleAssignment, error) {
	url := fmt.Sprintf("%s/roleManagement/directory/roleAssignmentScheduleInstances?$expand=roleDefinition", betaBaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value []struct {
			ID                     string `json:"id"`
			RoleDefinitionID       string `json:"roleDefinitionId"`
			PrincipalID            string `json:"principalId"`
			DirectoryScopeID       string `json:"directoryScopeId"`
			StartDateTime          string `json:"startDateTime"`
			EndDateTime            string `json:"endDateTime"`
			AssignmentType         string `json:"assignmentType"`
			MemberType             string `json:"memberType"`
			RoleDefinition         struct {
				DisplayName string `json:"displayName"`
			} `json:"roleDefinition"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter client-side for the current principal
	roles := make([]models.RoleAssignment, 0)
	for _, item := range result.Value {
		// Only include roles for the current principal
		if item.PrincipalID != c.principalID {
			continue
		}

		startTime, _ := time.Parse(time.RFC3339, item.StartDateTime)
		endTime, _ := time.Parse(time.RFC3339, item.EndDateTime)

		roles = append(roles, models.RoleAssignment{
			ID:               item.ID,
			RoleDefinitionID: item.RoleDefinitionID,
			RoleName:         item.RoleDefinition.DisplayName,
			PrincipalID:      item.PrincipalID,
			Scope:            item.DirectoryScopeID,
			Status:           "Active",
			Type:             models.RoleTypeAzureAD,
			StartDateTime:    startTime,
			EndDateTime:      endTime,
			IsEligible:       false,
		})
	}

	return roles, nil
}

// ActivateRole activates an eligible Azure AD role
func (c *AzureADPIMClient) ActivateRole(req models.ActivationRequest) error {
	url := fmt.Sprintf("%s/roleManagement/directory/roleAssignmentScheduleRequests", betaBaseURL)

	payload := map[string]interface{}{
		"action":           "selfActivate",
		"principalId":      c.principalID,
		"roleDefinitionId": req.RoleDefinitionID,
		"directoryScopeId": "/",
		"justification":    req.Justification,
		"scheduleInfo": map[string]interface{}{
			"startDateTime": time.Now().UTC().Format(time.RFC3339),
			"expiration": map[string]interface{}{
				"type":     "AfterDuration",
				"duration": req.Duration,
			},
		},
	}

	if req.TicketNumber != "" {
		payload["ticketInfo"] = map[string]interface{}{
			"ticketNumber": req.TicketNumber,
			"ticketSystem": req.TicketSystem,
		}
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("activation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeactivateRole deactivates an active Azure AD role
func (c *AzureADPIMClient) DeactivateRole(roleDefinitionID string) error {
	url := fmt.Sprintf("%s/roleManagement/directory/roleAssignmentScheduleRequests", betaBaseURL)

	payload := map[string]interface{}{
		"action":           "selfDeactivate",
		"principalId":      c.principalID,
		"roleDefinitionId": roleDefinitionID,
		"directoryScopeId": "/",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.accessToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deactivation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetPrincipalID retrieves the principal ID for the current user
func GetPrincipalID(accessToken string) (string, error) {
	url := fmt.Sprintf("%s/me", graphBaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user info with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.ID, nil
}
