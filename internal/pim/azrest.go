package pim

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// ActivateRoleViaAzCLI activates a role using az rest (preserves ACRS context)
func ActivateRoleViaAzCLI(pimType PIMType, roleDefID, resourceID, subjectID, justification, duration string) error {
	apiURL := fmt.Sprintf("https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/%s/roleAssignmentRequests", pimType)

	payload := map[string]interface{}{
		"roleDefinitionId": roleDefID,
		"resourceId":       resourceID,
		"subjectId":        subjectID,
		"assignmentState":  "Active",
		"type":             "UserAdd",
		"reason":           justification,
		"schedule": map[string]interface{}{
			"type":          "Once",
			"startDateTime": nil,
			"duration":      duration,
		},
	}

	return azRestPost(apiURL, payload)
}

// DeactivateRoleViaAzCLI deactivates a role using az rest
func DeactivateRoleViaAzCLI(pimType PIMType, roleDefID, resourceID, subjectID string) error {
	apiURL := fmt.Sprintf("https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/%s/roleAssignmentRequests", pimType)

	payload := map[string]interface{}{
		"roleDefinitionId": roleDefID,
		"resourceId":       resourceID,
		"subjectId":        subjectID,
		"assignmentState":  "Active",
		"type":             "UserRemove",
	}

	return azRestPost(apiURL, payload)
}

// azRestPost marshals payload to a temp file and calls az rest --body @file,
// preventing sensitive values from appearing in the process list.
func azRestPost(apiURL string, payload map[string]interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "pim-body-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(jsonData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	cmd := exec.Command("az", "rest",
		"--method", "POST",
		"--resource", "https://api.azrbac.mspim.azure.com",
		"--url", apiURL,
		"--headers", "Content-Type=application/json",
		"--body", "@"+tmpPath)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err == nil {
		return nil
	}

	if isMFAError(outputStr) {
		return &MFARequiredError{
			StatusCode: 400,
			Body:       outputStr,
			ClaimValue: extractClaimFromOutput(outputStr),
		}
	}

	return fmt.Errorf("az rest request failed: %w", err)
}

// Helper to check if error is MFA-related
func isMFAError(output string) bool {
	mfaKeywords := []string{
		"AcrsValidationFailed",
		"MfaRule",
		"Multifactor",
		"StrongAuthenticationRequired",
		"InteractionRequired",
		"ConditionalAccessPolicy",
		"claims=",
	}

	outputLower := strings.ToLower(output)
	for _, keyword := range mfaKeywords {
		if strings.Contains(outputLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// Extract claim value from error output
func extractClaimFromOutput(output string) string {
	if idx := strings.Index(output, "claims="); idx != -1 {
		rest := output[idx+7:]
		endChars := []string{"\"", "&", ")", " ", "\n"}
		endIdx := len(rest)
		for _, char := range endChars {
			if i := strings.Index(rest, char); i != -1 && i < endIdx {
				endIdx = i
			}
		}
		return rest[:endIdx]
	}
	return ""
}

// ActivateRoleAzRest wraps the az rest activation for the UnifiedPIMClient
func (c *UnifiedPIMClient) ActivateRoleAzRest(roleDefID, resourceID, justification, duration string) error {
	return ActivateRoleViaAzCLI(c.pimType, roleDefID, resourceID, c.principalID, justification, duration)
}

// DeactivateRoleAzRest wraps the az rest deactivation for the UnifiedPIMClient
func (c *UnifiedPIMClient) DeactivateRoleAzRest(roleDefID, resourceID string) error {
	return DeactivateRoleViaAzCLI(c.pimType, roleDefID, resourceID, c.principalID)
}

// GetMaxDurationViaAzCLI fetches the maximum allowed duration using az rest
func GetMaxDurationViaAzCLI(pimType PIMType, resourceID, roleDefID string) (int, error) {
	filter := fmt.Sprintf("(resource/id eq '%s') and (roleDefinition/id eq '%s')", resourceID, roleDefID)
	apiURL := fmt.Sprintf("https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/%s/roleSettings?$filter=%s",
		pimType, url.QueryEscape(filter))

	cmd := exec.Command("az", "rest",
		"--method", "GET",
		"--resource", "https://api.azrbac.mspim.azure.com",
		"--url", apiURL)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 300, nil
	}

	var result struct {
		Value []struct {
			UserMemberSettings []struct {
				RuleIdentifier string `json:"ruleIdentifier"`
				Setting        string `json:"setting"`
			} `json:"userMemberSettings"`
		} `json:"value"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return 300, nil
	}

	for _, policy := range result.Value {
		for _, setting := range policy.UserMemberSettings {
			if setting.RuleIdentifier == "ExpirationRule" {
				var expirationSettings struct {
					MaximumGrantPeriodInMinutes int `json:"maximumGrantPeriodInMinutes"`
				}
				if err := json.Unmarshal([]byte(setting.Setting), &expirationSettings); err == nil {
					if expirationSettings.MaximumGrantPeriodInMinutes > 0 {
						return expirationSettings.MaximumGrantPeriodInMinutes, nil
					}
				}
			}
		}
	}

	return 300, nil
}

// GetMaxDurationAzRest wraps the az rest policy fetching for the UnifiedPIMClient
func (c *UnifiedPIMClient) GetMaxDurationAzRest(resourceID, roleDefID string) (int, error) {
	return GetMaxDurationViaAzCLI(c.pimType, resourceID, roleDefID)
}

