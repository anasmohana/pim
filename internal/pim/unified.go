package pim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"pim-manager/pkg/models"
	"regexp"
	"strings"
	"time"
)

const (
	// MS PIM API base URL - same as bash script
	msPIMBaseURL = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess"
)

// PIMType represents the type of PIM roles
type PIMType string

const (
	PIMTypeGroups         PIMType = "aadGroups"
	PIMTypeAzureResources PIMType = "azureResources"
	PIMTypeEntraRoles     PIMType = "aadroles"
)

// UnifiedPIMClient handles all PIM operations using the MS PIM API
type UnifiedPIMClient struct {
	accessToken string
	principalID string
	pimType     PIMType
}

// NewUnifiedPIMClient creates a new unified PIM client
func NewUnifiedPIMClient(accessToken, principalID string, pimType PIMType) *UnifiedPIMClient {
	return &UnifiedPIMClient{
		accessToken: accessToken,
		principalID: principalID,
		pimType:     pimType,
	}
}

// ListEligibleRoles lists all eligible roles for the given PIM type
func (c *UnifiedPIMClient) ListEligibleRoles() ([]models.RoleAssignment, error) {
	return c.listRoles("Eligible")
}

// ListActiveRoles lists all active role assignments for the given PIM type
func (c *UnifiedPIMClient) ListActiveRoles() ([]models.RoleAssignment, error) {
	return c.listRoles("Active")
}

// listRoles is a helper function to list roles by state (Eligible or Active)
func (c *UnifiedPIMClient) listRoles(state string) ([]models.RoleAssignment, error) {
	filter := fmt.Sprintf("(subject/id eq '%s') and (assignmentState eq '%s')", c.principalID, state)
	apiURL := fmt.Sprintf("%s/%s/roleAssignments?$expand=roleDefinition($expand=resource)&$filter=%s",
		msPIMBaseURL, c.pimType, url.QueryEscape(filter))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Check for MFA/ACRS errors
		if c.isMFARequired(resp.StatusCode, string(body)) {
			return nil, &MFARequiredError{
				StatusCode: resp.StatusCode,
				Body:       string(body),
			}
		}
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID                               string `json:"id"`
			ResourceID                       string `json:"resourceId"`
			RoleDefinitionID                 string `json:"roleDefinitionId"`
			SubjectID                        string `json:"subjectId"`
			AssignmentState                  string `json:"assignmentState"`
			LinkedEligibleRoleAssignmentID   string `json:"linkedEligibleRoleAssignmentId"`
			RoleDefinition                   struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				Resource    struct {
					ID          string `json:"id"`
					DisplayName string `json:"displayName"`
					Type        string `json:"type"`
				} `json:"resource"`
			} `json:"roleDefinition"`
			StartDateTime string `json:"startDateTime"`
			EndDateTime   string `json:"endDateTime"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	roles := make([]models.RoleAssignment, 0)
	for _, item := range result.Value {
		startTime, _ := time.Parse(time.RFC3339, item.StartDateTime)
		endTime, _ := time.Parse(time.RFC3339, item.EndDateTime)

		// Build display name based on PIM type
		displayName := c.buildDisplayName(item.RoleDefinition.DisplayName, item.RoleDefinition.Resource.DisplayName)

		role := models.RoleAssignment{
			ID:                             item.ID,
			RoleDefinitionID:               item.RoleDefinitionID,
			ResourceID:                     item.ResourceID,
			RoleName:                       displayName,
			PrincipalID:                    item.SubjectID,
			Scope:                          item.RoleDefinition.Resource.DisplayName,
			Status:                         state,
			Type:                           c.convertPIMType(),
			StartDateTime:                  startTime,
			EndDateTime:                    endTime,
			IsEligible:                     state == "Eligible",
			LinkedEligibleRoleAssignmentID: item.LinkedEligibleRoleAssignmentID,
		}

		roles = append(roles, role)
	}

	return roles, nil
}

// ActivateRole activates an eligible role
func (c *UnifiedPIMClient) ActivateRole(roleDefID, resourceID, justification, duration string) error {
	apiURL := fmt.Sprintf("%s/%s/roleAssignmentRequests", msPIMBaseURL, c.pimType)

	payload := map[string]interface{}{
		"roleDefinitionId": roleDefID,
		"resourceId":       resourceID,
		"subjectId":        c.principalID,
		"assignmentState":  "Active",
		"type":             "UserAdd",
		"reason":           justification,
		"schedule": map[string]interface{}{
			"type":          "Once",
			"startDateTime": nil,
			"duration":      duration,
		},
	}

	return c.executeRoleRequest(apiURL, payload)
}

// DeactivateRole deactivates an active role
func (c *UnifiedPIMClient) DeactivateRole(roleDefID, resourceID string) error {
	apiURL := fmt.Sprintf("%s/%s/roleAssignmentRequests", msPIMBaseURL, c.pimType)

	payload := map[string]interface{}{
		"roleDefinitionId": roleDefID,
		"resourceId":       resourceID,
		"subjectId":        c.principalID,
		"assignmentState":  "Active",
		"type":             "UserRemove",
	}

	return c.executeRoleRequest(apiURL, payload)
}

// GetMaxDuration fetches the maximum allowed duration for a role
func (c *UnifiedPIMClient) GetMaxDuration(resourceID, roleDefID string) (int, error) {
	filter := fmt.Sprintf("(resource/id eq '%s') and (roleDefinition/id eq '%s')", resourceID, roleDefID)
	apiURL := fmt.Sprintf("%s/%s/roleSettings?$filter=%s",
		msPIMBaseURL, c.pimType, url.QueryEscape(filter))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return 60, err // Default 1 hour
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 60, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 60, nil // Default fallback
	}

	var result struct {
		Value []struct {
			LifeCycleManagement []struct {
				Caller string `json:"caller"`
				Level  string `json:"level"`
				Value  []struct {
					RuleIdentifier string `json:"ruleIdentifier"`
					Setting        string `json:"setting"`
				} `json:"value"`
			} `json:"lifeCycleManagement"`
		} `json:"value"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		return 60, err
	}

	// Parse the policy settings
	for _, policy := range result.Value {
		for _, lifecycle := range policy.LifeCycleManagement {
			if lifecycle.Caller == "EndUser" && lifecycle.Level == "Member" {
				for _, rule := range lifecycle.Value {
					if rule.RuleIdentifier == "ExpirationRule" {
						// Parse the JSON setting
						var setting struct {
							MaximumGrantPeriodInMinutes int `json:"maximumGrantPeriodInMinutes"`
						}
						if err := json.Unmarshal([]byte(rule.Setting), &setting); err == nil {
							if setting.MaximumGrantPeriodInMinutes > 0 {
								return setting.MaximumGrantPeriodInMinutes, nil
							}
						}
					}
				}
			}
		}
	}

	return 60, nil // Default 1 hour
}

// executeRoleRequest is a helper to execute role activation/deactivation requests
func (c *UnifiedPIMClient) executeRoleRequest(apiURL string, payload map[string]interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Check for MFA/ACRS errors
		if c.isMFARequired(resp.StatusCode, string(body)) {
			return &MFARequiredError{
				StatusCode: resp.StatusCode,
				Body:       string(body),
				ClaimValue: c.extractClaimValue(string(body)),
			}
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	return nil
}

// isMFARequired checks if the error indicates MFA/ACRS is required
func (c *UnifiedPIMClient) isMFARequired(statusCode int, body string) bool {
	if statusCode != 400 && statusCode != 401 {
		return false
	}

	mfaKeywords := []string{
		"AcrsValidationFailed",
		"MfaRule",
		"Multifactor",
		"StrongAuthenticationRequired",
		"InteractionRequired",
		"ConditionalAccessPolicy",
		"claims=",
	}

	bodyLower := strings.ToLower(body)
	for _, keyword := range mfaKeywords {
		if strings.Contains(bodyLower, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// extractClaimValue extracts the claims challenge from an error response
func (c *UnifiedPIMClient) extractClaimValue(body string) string {
	// Look for claims= in the error response
	re := regexp.MustCompile(`claims=([^"&)]+)`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// buildDisplayName creates a display name based on PIM type
func (c *UnifiedPIMClient) buildDisplayName(roleName, resourceName string) string {
	switch c.pimType {
	case PIMTypeGroups:
		return resourceName
	case PIMTypeAzureResources:
		return fmt.Sprintf("%s -> %s", roleName, resourceName)
	case PIMTypeEntraRoles:
		return roleName
	default:
		return roleName
	}
}

// convertPIMType converts PIMType to models.RoleType
func (c *UnifiedPIMClient) convertPIMType() models.RoleType {
	switch c.pimType {
	case PIMTypeGroups:
		return models.RoleTypeGroups
	case PIMTypeAzureResources:
		return models.RoleTypeAzureResource
	case PIMTypeEntraRoles:
		return models.RoleTypeEntraRoles
	default:
		return models.RoleTypeAzureResource
	}
}

// MFARequiredError represents an error that requires MFA/ACRS authentication
type MFARequiredError struct {
	StatusCode int
	Body       string
	ClaimValue string
}

func (e *MFARequiredError) Error() string {
	return fmt.Sprintf("MFA/ACRS authentication required (status %d)", e.StatusCode)
}
