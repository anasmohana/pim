package pim

import (
	"encoding/json"
	"fmt"
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

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Use az rest instead of direct HTTP - this preserves ACRS context
	cmd := exec.Command("az", "rest",
		"--method", "POST",
		"--resource", "https://api.azrbac.mspim.azure.com",
		"--url", apiURL,
		"--headers", "Content-Type=application/json",
		"--body", string(jsonData))

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check for success (even with warnings in output)
	if err == nil {
		return nil
	}

	// Check if it's an MFA error
	if isMFAError(outputStr) {
		return &MFARequiredError{
			StatusCode: 400,
			Body:       outputStr,
			ClaimValue: extractClaimFromOutput(outputStr),
		}
	}

	// Return the full error with output
	return fmt.Errorf("activation failed: %w\nOutput: %s", err, outputStr)
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

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	cmd := exec.Command("az", "rest",
		"--method", "POST",
		"--resource", "https://api.azrbac.mspim.azure.com",
		"--url", apiURL,
		"--headers", "Content-Type=application/json",
		"--body", string(jsonData))

	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		if isMFAError(outputStr) {
			return &MFARequiredError{
				StatusCode: 400,
				Body:       outputStr,
				ClaimValue: extractClaimFromOutput(outputStr),
			}
		}
		return fmt.Errorf("deactivation failed: %s", string(output))
	}

	return nil
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
	// Look for claims= in the error
	if idx := strings.Index(output, "claims="); idx != -1 {
		rest := output[idx+7:] // Skip "claims="
		// Find end of claim value (usually at quote, ampersand, or closing paren)
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
