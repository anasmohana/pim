package main

import (
	"bufio"
	"fmt"
	"os"
	"pim-manager/internal/auth"
	"pim-manager/internal/pim"
	"pim-manager/pkg/models"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/manifoldco/promptui"
)

func main() {
	args := os.Args[1:]

	// Parse command-line arguments
	pimType, mode, roleName := parseArgs(args)

	if pimType == "" {
		// No PIM type specified - show selection menu
		pimType = selectPIMType(mode)
	}

	switch mode {
	case "deactivate":
		handleDeactivate(pimType, roleName)
	default:
		handleActivate(pimType, roleName)
	}
}

// parseArgs parses command-line arguments and returns (pimType, mode, roleName)
func parseArgs(args []string) (string, string, string) {
	pimType := ""
	mode := "activate"
	roleName := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-h", "--help", "help":
			printUsage()
			os.Exit(0)
		case "-g", "--group":
			pimType = string(pim.PIMTypeGroups)
			// Check if next arg is a role name
			if i+1 < len(args) && !isFlag(args[i+1]) && args[i+1] != "d" && args[i+1] != "deactivate" {
				roleName = args[i+1]
				i++
			}
		case "-r", "--resource":
			pimType = string(pim.PIMTypeAzureResources)
			if i+1 < len(args) && !isFlag(args[i+1]) && args[i+1] != "d" && args[i+1] != "deactivate" {
				roleName = args[i+1]
				i++
			}
		case "-e", "--entra":
			pimType = string(pim.PIMTypeEntraRoles)
			if i+1 < len(args) && !isFlag(args[i+1]) && args[i+1] != "d" && args[i+1] != "deactivate" {
				roleName = args[i+1]
				i++
			}
		case "d", "deactivate":
			mode = "deactivate"
		default:
			if !isFlag(arg) && roleName == "" {
				roleName = arg
			}
		}
	}

	return pimType, mode, roleName
}

func isFlag(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func printUsage() {
	fmt.Println("Azure PIM Activator")
	fmt.Println()
	fmt.Println("Usage: pim [OPTIONS] [ACTION]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -h, --help          Show this help message")
	fmt.Println("  -g, --group [NAME]  PIM type: Azure AD Groups")
	fmt.Println("  -r, --resource [NAME] PIM type: Azure Resources")
	fmt.Println("  -e, --entra [NAME]  PIM type: Microsoft Entra Roles")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  deactivate, d       Deactivate an active role")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pim                     # Interactive mode with PIM type selection")
	fmt.Println("  pim -g                  # List and activate Azure AD Groups")
	fmt.Println("  pim -g my-group-name    # Activate specific group")
	fmt.Println("  pim -r                  # List and activate Azure Resources")
	fmt.Println("  pim -e                  # List and activate Entra Roles")
	fmt.Println("  pim d -g                # Deactivate a group role")
	fmt.Println("  pim deactivate -r       # Deactivate a resource role")
}

func selectPIMType(mode string) string {
	if mode == "deactivate" {
		fmt.Println("╔═══════════════════════════════════════╗")
		fmt.Println("║   Azure PIM Deactivator               ║")
		fmt.Println("╚═══════════════════════════════════════╝")
	} else {
		fmt.Println("╔═══════════════════════════════════════╗")
		fmt.Println("║   Welcome to Azure PIM Activator!     ║")
		fmt.Println("╚═══════════════════════════════════════╝")
	}

	items := []string{"Groups", "Azure Resources", "Entra Roles"}

	prompt := promptui.Select{
		Label: "Select PIM type",
		Items: items,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}:",
			Active:   "▸ {{ . | cyan }}",
			Inactive: "  {{ . }}",
			Selected: "✓ {{ . | green }}",
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Println("\nExiting...")
		os.Exit(0)
	}

	fmt.Println()

	switch index {
	case 0:
		return string(pim.PIMTypeGroups)
	case 1:
		return string(pim.PIMTypeAzureResources)
	case 2:
		return string(pim.PIMTypeEntraRoles)
	default:
		os.Exit(1)
		return ""
	}
}

func handleActivate(pimTypeStr, roleName string) {
	fmt.Println("╔═══════════════════════════════════════╗")
	fmt.Printf("║   Azure PIM Activator (%s)%s║\n", getPIMLabel(pimTypeStr), strings.Repeat(" ", 14-len(getPIMLabel(pimTypeStr))))
	fmt.Println("╚═══════════════════════════════════════╝")

	// Get authentication
	fmt.Println("\nVerifying credentials...")
	ctx, err := auth.GetAzureContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	pimToken, err := auth.GetPIMToken()
	if err != nil {
		fmt.Printf("Failed to get PIM token: %v\n", err)
		fmt.Println("\nHint: Try running 'az login' first")
		os.Exit(1)
	}

	client := pim.NewUnifiedPIMClient(pimToken, principalID, pim.PIMType(pimTypeStr))

	// Get eligible and active roles
	fmt.Printf("Searching for activatable %ss...\n", getPIMLabel(pimTypeStr))

	eligibleRoles, err := client.ListEligibleRoles()
	if err != nil {
		if mfaErr, ok := err.(*pim.MFARequiredError); ok {
			handleMFAError(mfaErr, pimTypeStr, principalID, roleName, "activate")
			return
		}
		fmt.Printf("Failed to fetch eligible roles: %v\n", err)
		os.Exit(1)
	}

	activeRoles, _ := client.ListActiveRoles()

	// Filter out already-active roles
	availableRoles := filterActiveRoles(eligibleRoles, activeRoles)

	if len(availableRoles) == 0 {
		fmt.Printf("\n✓ No eligible %ss to activate (all active or none available).\n", getPIMLabel(pimTypeStr))
		return
	}

	// If role name specified, activate directly
	if roleName != "" {
		activateRoleByName(client, availableRoles, roleName, pimTypeStr)
		return
	}

	// Interactive selection
	selectedRole := selectRole(availableRoles, "activate")
	if selectedRole == nil {
		fmt.Println("👋 Cancelled")
		return
	}

	// Activate the role
	activateSelectedRole(client, selectedRole, pimTypeStr)
}

func handleDeactivate(pimTypeStr, roleName string) {
	fmt.Println("╔═══════════════════════════════════════╗")
	fmt.Printf("║   Selected PIM: %ss%s║\n", getPIMLabel(pimTypeStr), strings.Repeat(" ", 21-len(getPIMLabel(pimTypeStr))))
	fmt.Println("╚═══════════════════════════════════════╝")

	// Get authentication
	fmt.Println("\nVerifying credentials...")
	ctx, err := auth.GetAzureContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	pimToken, err := auth.GetPIMToken()
	if err != nil {
		fmt.Printf("Failed to get PIM token: %v\n", err)
		os.Exit(1)
	}

	client := pim.NewUnifiedPIMClient(pimToken, principalID, pim.PIMType(pimTypeStr))

	// Get active roles
	fmt.Printf("Searching for active %ss...\n", getPIMLabel(pimTypeStr))

	activeRoles, err := client.ListActiveRoles()
	if err != nil {
		if mfaErr, ok := err.(*pim.MFARequiredError); ok {
			handleMFAError(mfaErr, pimTypeStr, principalID, roleName, "deactivate")
			return
		}
		fmt.Printf("Failed to fetch active roles: %v\n", err)
		os.Exit(1)
	}

	// Filter only deactivatable roles (those with linkedEligibleRoleAssignmentId)
	deactivatable := make([]models.RoleAssignment, 0)
	for _, role := range activeRoles {
		if role.LinkedEligibleRoleAssignmentID != "" {
			deactivatable = append(deactivatable, role)
		}
	}

	if len(deactivatable) == 0 {
		fmt.Printf("\n✓ No active %ss to deactivate.\n", getPIMLabel(pimTypeStr))
		return
	}

	// If role name specified, deactivate directly
	if roleName != "" {
		deactivateRoleByName(client, deactivatable, roleName, pimTypeStr)
		return
	}

	// Interactive selection
	selectedRole := selectRole(deactivatable, "deactivate")
	if selectedRole == nil {
		fmt.Println("👋 Cancelled")
		return
	}

	// Deactivate the role using az rest
	fmt.Printf("Deactivating: %s...\n", selectedRole.RoleName)

	err = client.DeactivateRoleAzRest(selectedRole.RoleDefinitionID, selectedRole.ResourceID)
	if err != nil {
		if mfaErr, ok := err.(*pim.MFARequiredError); ok {
			if handleMFAReauth(mfaErr) {
				// Retry after MFA - az rest handles the token
				fmt.Println("✓ Authentication successful. Retrying deactivation...")
				err = client.DeactivateRoleAzRest(selectedRole.RoleDefinitionID, selectedRole.ResourceID)
				if err == nil {
					fmt.Printf("✓ Deactivated: %s\n", selectedRole.RoleName)
					return
				}
			}
		}

		if strings.Contains(err.Error(), "ActiveDurationTooShort") {
			fmt.Printf("❌ Error: '%s' was activated less than 5 minutes ago. This role needs to be active for at least 5 minutes before it can be deactivated 🤷\n", selectedRole.RoleName)
		} else {
			fmt.Printf("❌ Failed to deactivate '%s': %v\n", selectedRole.RoleName, err)
		}
		os.Exit(1)
	}

	fmt.Printf("✓ Deactivated: %s\n", selectedRole.RoleName)
}

func activateRoleByName(client *pim.UnifiedPIMClient, roles []models.RoleAssignment, name, pimTypeStr string) {
	// Find role by name
	var found *models.RoleAssignment
	for i := range roles {
		if strings.EqualFold(roles[i].RoleName, name) || strings.Contains(strings.ToLower(roles[i].RoleName), strings.ToLower(name)) {
			found = &roles[i]
			break
		}
	}

	if found == nil {
		fmt.Printf("❌ '%s' not found in eligible %ss.\n", name, getPIMLabel(pimTypeStr))
		os.Exit(1)
	}

	activateSelectedRole(client, found, pimTypeStr)
}

func deactivateRoleByName(client *pim.UnifiedPIMClient, roles []models.RoleAssignment, name, pimTypeStr string) {
	// Find role by name
	var found *models.RoleAssignment
	for i := range roles {
		if strings.EqualFold(roles[i].RoleName, name) || strings.Contains(strings.ToLower(roles[i].RoleName), strings.ToLower(name)) {
			found = &roles[i]
			break
		}
	}

	if found == nil {
		fmt.Printf("❌ '%s' not found in active %ss.\n", name, getPIMLabel(pimTypeStr))
		os.Exit(1)
	}

	fmt.Printf("Deactivating: %s...\n", found.RoleName)
	err := client.DeactivateRoleAzRest(found.RoleDefinitionID, found.ResourceID)
	if err != nil {
		fmt.Printf("❌ Failed to deactivate '%s': %v\n", found.RoleName, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Deactivated: %s\n", found.RoleName)
}

func activateSelectedRole(client *pim.UnifiedPIMClient, role *models.RoleAssignment, pimTypeStr string) {
	fmt.Printf("\n✓ Selected: %s\n\n", role.RoleName)

	// Fetch max duration using az rest
	fmt.Println("Fetching role policy...")
	maxMinutes, err := client.GetMaxDurationAzRest(role.ResourceID, role.RoleDefinitionID)
	if err != nil {
		maxMinutes = 300 // Default to 5 hours
	}
	maxHours := maxMinutes / 60
	if maxHours == 0 {
		maxHours = 1
	}
	fmt.Printf("✓ Maximum allowed duration: %d hours\n\n", maxHours)

	// Get justification
	reader := bufio.NewReader(os.Stdin)
	var justification string
	for {
		fmt.Print("Enter justification (reason for activation): ")
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("⚠ Error reading input. Please try again.")
			continue
		}

		justification = strings.TrimSpace(line)
		if justification == "" {
			justification = "Routine administrative access"
			break
		}
		break
	}

	// Get duration
	var durationHours int
	for {
		fmt.Printf("Enter duration in hours (default: %d, max: %d): ", maxHours, maxHours)
		var input string
		fmt.Scanln(&input)

		if input == "" {
			durationHours = maxHours
			break
		}

		_, err := fmt.Sscanf(input, "%d", &durationHours)
		if err != nil || durationHours <= 0 {
			fmt.Println("⚠ Invalid duration. Please enter a positive number.")
			continue
		}

		if durationHours > maxHours {
			fmt.Printf("⚠ Duration exceeds maximum allowed (%d hours). Please try again.\n", maxHours)
			continue
		}

		break
	}

	duration := fmt.Sprintf("PT%dH", durationHours)

	// Activate using az rest (preserves ACRS context)
	fmt.Printf("\nActivating: %s...\n", role.RoleName)

	err = client.ActivateRoleAzRest(role.RoleDefinitionID, role.ResourceID, justification, duration)
	if err != nil {
		if mfaErr, ok := err.(*pim.MFARequiredError); ok {
			if handleMFAReauth(mfaErr) {
				// Retry activation after MFA - az rest handles the token automatically
				fmt.Println("✓ Authentication successful. Retrying activation...")

				err = client.ActivateRoleAzRest(role.RoleDefinitionID, role.ResourceID, justification, duration)
				if err == nil {
					fmt.Printf("✓ Done: %s\n", role.RoleName)
					return
				}

				// If still failing, might be duration issue
				if strings.Contains(err.Error(), "ExpirationRule") || strings.Contains(err.Error(), "duration") {
					fmt.Printf("⏱️  Adjusting duration to maximum allowed: PT%dM...\n", maxMinutes)
					duration = fmt.Sprintf("PT%dM", maxMinutes)
					err = client.ActivateRoleAzRest(role.RoleDefinitionID, role.ResourceID, justification, duration)
					if err == nil {
						fmt.Printf("✓ Done: %s\n", role.RoleName)
						return
					}
				}
			}
		}

		// Check if duration is too long
		if strings.Contains(err.Error(), "ExpirationRule") || strings.Contains(err.Error(), "duration") {
			fmt.Printf("⏱️  Duration too long, using maximum allowed: PT%dM...\n", maxMinutes)
			duration = fmt.Sprintf("PT%dM", maxMinutes)
			err = client.ActivateRoleAzRest(role.RoleDefinitionID, role.ResourceID, justification, duration)
			if err == nil {
				fmt.Printf("✓ Done: %s\n", role.RoleName)
				return
			}
		}

		fmt.Printf("❌ Failed to activate '%s': %v\n", role.RoleName, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Done: %s\n", role.RoleName)
}

func selectRole(roles []models.RoleAssignment, action string) *models.RoleAssignment {
	// Build items list with "All" option
	items := make([]string, len(roles)+1)
	items[0] = "All"
	for i, role := range roles {
		items[i+1] = role.RoleName
	}

	prompt := promptui.Select{
		Label: fmt.Sprintf("Select a role to %s", action),
		Items: items,
		Size:  20,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}:",
			Active:   "▸ {{ . | cyan }}",
			Inactive: "  {{ . }}",
			Selected: "✓ {{ . | green }}",
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Println("\n👋 Cancelled")
		return nil
	}

	if index == 0 {
		// Activate/deactivate all
		fmt.Println()
		ctx, _ := auth.GetAzureContext()
		principalID, _ := pim.GetPrincipalID(ctx.AccessToken)
		pimToken, _ := auth.GetPIMToken()

		for _, role := range roles {
			client := pim.NewUnifiedPIMClient(pimToken, principalID, pim.PIMType(string(role.Type)))

			if action == "activate" {
				fmt.Printf("Activating: %s...\n", role.RoleName)
				// Quick activation with defaults using az rest
				err := client.ActivateRoleAzRest(role.RoleDefinitionID, role.ResourceID, "Routine administrative access", "PT8H")
				if err != nil {
					fmt.Printf("❌ Failed: %v\n", err)
				} else {
					fmt.Printf("✓ Done: %s\n", role.RoleName)
				}
			} else {
				fmt.Printf("Deactivating: %s...\n", role.RoleName)
				err := client.DeactivateRoleAzRest(role.RoleDefinitionID, role.ResourceID)
				if err != nil {
					fmt.Printf("❌ Failed: %v\n", err)
				} else {
					fmt.Printf("✓ Deactivated: %s\n", role.RoleName)
				}
			}
		}
		os.Exit(0)
		return nil
	}

	// Return the selected role (index-1 because of "All" at position 0)
	return &roles[index-1]
}

func filterActiveRoles(eligible, active []models.RoleAssignment) []models.RoleAssignment {
	activeMap := make(map[string]bool)
	for _, a := range active {
		key := a.RoleName
		activeMap[key] = true
	}

	available := make([]models.RoleAssignment, 0)
	for _, e := range eligible {
		if !activeMap[e.RoleName] {
			available = append(available, e)
		}
	}

	return available
}

func getPIMLabel(pimType string) string {
	switch pimType {
	case string(pim.PIMTypeGroups):
		return "group"
	case string(pim.PIMTypeAzureResources):
		return "resource role"
	case string(pim.PIMTypeEntraRoles):
		return "entra role"
	default:
		return "role"
	}
}

func handleMFAError(mfaErr *pim.MFARequiredError, pimTypeStr, principalID, roleName, mode string) {
	fmt.Printf("🔐 Authentication required. Opening browser...\n")

	if handleMFAReauth(mfaErr) {
		// Retry the operation
		fmt.Println("✓ Authentication successful. Retrying...")

		// Recursively retry
		if mode == "activate" {
			handleActivate(pimTypeStr, roleName)
		} else {
			handleDeactivate(pimTypeStr, roleName)
		}
		return
	}

	fmt.Println("❌ Authentication failed.")
	os.Exit(1)
}

func handleMFAReauth(mfaErr *pim.MFARequiredError) bool {
	if mfaErr.ClaimValue != "" {
		err := auth.ReauthenticateWithClaims(mfaErr.ClaimValue)
		return err == nil
	} else {
		err := auth.SimpleReauthenticate()
		return err == nil
	}
}

func printRoles(roles []models.RoleAssignment) {
	if len(roles) == 0 {
		fmt.Println("No roles found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ROLE NAME\tSTATUS\tEXPIRES")
	fmt.Fprintln(w, "---------\t------\t-------")

	for _, role := range roles {
		expiresIn := ""
		if !role.EndDateTime.IsZero() {
			if role.Status == "Active" {
				duration := time.Until(role.EndDateTime)
				if duration > 0 {
					expiresIn = formatDuration(duration)
				} else {
					expiresIn = "Expired"
				}
			} else {
				expiresIn = role.EndDateTime.Format("2006-01-02")
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\n",
			role.RoleName,
			role.Status,
			expiresIn,
		)
	}

	w.Flush()
	fmt.Println()
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 24 {
		days := hours / 24
		hours = hours % 24
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
