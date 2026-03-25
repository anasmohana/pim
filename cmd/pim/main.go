package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"pim-manager/internal/auth"
	"pim-manager/internal/pim"
	"pim-manager/pkg/models"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		// No command provided - run interactive mode
		handleInteractive()
		return
	}

	command := os.Args[1]

	switch command {
	case "list":
		handleList()
	case "activate":
		handleActivate()
	case "deactivate":
		handleDeactivate()
	case "status":
		handleStatus()
	case "interactive", "i":
		handleInteractive()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("PIM Manager - Manage Azure PIM role activations")
	fmt.Println("\nUsage: pim [command] [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  (none)       Interactive mode - select and activate roles interactively (default)")
	fmt.Println("  list         List all eligible PIM roles")
	fmt.Println("  activate     Activate a PIM role manually")
	fmt.Println("  deactivate   Deactivate an active PIM role")
	fmt.Println("  status       Show active role assignments")
	fmt.Println("  help         Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  pim                    # Interactive mode")
	fmt.Println("  pim list              # List eligible roles")
	fmt.Println("  pim status            # Show active roles")
	fmt.Println("  pim activate --role-id <id> --justification \"Fix\" # Manual activation")
}

func handleList() {
	ctx, err := initializeContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Get principal ID
	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	// List Azure AD roles
	fmt.Println("\n=== Eligible Azure AD Roles ===")
	adClient := pim.NewAzureADPIMClient(ctx.AccessToken, principalID)
	adRoles, err := adClient.ListEligibleRoles()
	if err != nil {
		if strings.Contains(err.Error(), "PermissionScopeNotGranted") || strings.Contains(err.Error(), "403") {
			fmt.Println("⚠ Azure AD PIM requires additional permissions.")
			fmt.Println("  Azure CLI tokens don't include RoleManagement.Read.Directory scope.")
			fmt.Println("  Use --ad-auth for interactive authentication with PIM permissions.")
			fmt.Println("  Or use Azure Portal for Azure AD role management.")
		} else {
			fmt.Printf("Failed to list Azure AD roles: %v\n", err)
		}
	} else {
		printRoles(adRoles)
	}

	// List Azure Resource roles across all subscriptions
	fmt.Println("\n=== Eligible Azure Resource Roles (All Subscriptions) ===")

	subscriptions, err := auth.GetAllSubscriptions()
	if err != nil {
		fmt.Printf("Failed to get subscriptions: %v\n", err)
		os.Exit(1)
	}

	armToken, err := auth.GetAzureResourceToken()
	if err != nil {
		fmt.Printf("Failed to get ARM token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Checking %d subscription(s)...\n\n", len(subscriptions))

	allRoles := make([]models.RoleAssignment, 0)
	for _, sub := range subscriptions {
		// Skip subscriptions from different tenants to avoid 401 errors
		if sub.TenantID != ctx.TenantID {
			continue
		}

		resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, sub.ID)
		resourceRoles, err := resourceClient.ListEligibleRoles()
		if err != nil {
			// Only show errors for subscriptions in our tenant
			if !strings.Contains(err.Error(), "InvalidAuthenticationTokenTenant") {
				fmt.Printf("⚠ Subscription '%s': %v\n", sub.Name, err)
			}
			continue
		}

		// Add subscription name to each role
		for i := range resourceRoles {
			resourceRoles[i].SubscriptionName = sub.Name
		}

		allRoles = append(allRoles, resourceRoles...)
	}

	if len(allRoles) == 0 {
		fmt.Println("No eligible roles found across all subscriptions")
	} else {
		printRoles(allRoles)
	}
}

func handleStatus() {
	ctx, err := initializeContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	// List active Azure AD roles
	fmt.Println("\n=== Active Azure AD Roles ===")
	adClient := pim.NewAzureADPIMClient(ctx.AccessToken, principalID)
	adRoles, err := adClient.ListActiveRoles()
	if err != nil {
		if strings.Contains(err.Error(), "PermissionScopeNotGranted") || strings.Contains(err.Error(), "403") {
			fmt.Println("⚠ Azure AD PIM requires additional permissions.")
			fmt.Println("  Azure CLI tokens don't include RoleManagement.Read.Directory scope.")
		} else {
			fmt.Printf("Failed to list Azure AD roles: %v\n", err)
		}
	} else {
		printRoles(adRoles)
	}

	// List active Azure Resource roles across all subscriptions
	fmt.Println("\n=== Active Azure Resource Roles (All Subscriptions) ===")

	subscriptions, err := auth.GetAllSubscriptions()
	if err != nil {
		fmt.Printf("Failed to get subscriptions: %v\n", err)
		os.Exit(1)
	}

	armToken, err := auth.GetAzureResourceToken()
	if err != nil {
		fmt.Printf("Failed to get ARM token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Checking %d subscription(s)...\n\n", len(subscriptions))

	allActiveRoles := make([]models.RoleAssignment, 0)
	for _, sub := range subscriptions {
		// Skip subscriptions from different tenants
		if sub.TenantID != ctx.TenantID {
			continue
		}

		resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, sub.ID)
		resourceRoles, err := resourceClient.ListActiveRoles()
		if err != nil {
			continue // Silently skip subscriptions with errors
		}

		// Add subscription name to each role
		for i := range resourceRoles {
			resourceRoles[i].SubscriptionName = sub.Name
		}

		allActiveRoles = append(allActiveRoles, resourceRoles...)
	}

	if len(allActiveRoles) == 0 {
		fmt.Println("No active roles found across all subscriptions")
	} else {
		printRoles(allActiveRoles)
	}
}

func handleInteractive() {
	ctx, err := initializeContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n╔══════════════════════════════════════════╗")
	fmt.Println("║   PIM Manager - Interactive Mode        ║")
	fmt.Println("╚══════════════════════════════════════════╝")

	// Fetch all eligible roles
	fmt.Print("\nFetching subscriptions...")

	subscriptions, err := auth.GetAllSubscriptions()
	if err != nil {
		fmt.Printf("\nFailed to get subscriptions: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" found %d subscription(s)\n", len(subscriptions))

	armToken, err := auth.GetAzureResourceToken()
	if err != nil {
		fmt.Printf("Failed to get ARM token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Checking PIM roles across all subscriptions...")

	allRoles := make([]models.RoleAssignment, 0)
	checkedCount := 0
	for _, sub := range subscriptions {
		if sub.TenantID != ctx.TenantID {
			continue
		}

		checkedCount++
		fmt.Printf("  [%d/%d] %s...\r", checkedCount, len(subscriptions), sub.Name)

		resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, sub.ID)
		resourceRoles, err := resourceClient.ListEligibleRoles()
		if err != nil {
			continue
		}

		for i := range resourceRoles {
			resourceRoles[i].SubscriptionName = sub.Name
		}

		allRoles = append(allRoles, resourceRoles...)
	}
	fmt.Printf("\n")

	if len(allRoles) == 0 {
		fmt.Println("\n⚠ No eligible PIM roles found.")
		fmt.Println("Check Azure Portal to verify you have PIM role assignments.")
		return
	}

	// Display roles with numbers in table format
	fmt.Printf("\n✓ Found %d eligible role(s)\n\n", len(allRoles))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tSUBSCRIPTION\tROLE NAME\tRESOURCE\tEXPIRES")
	fmt.Fprintln(w, "-\t------------\t---------\t--------\t-------")

	for i, role := range allRoles {
		resource := extractResourceFromScope(role.Scope)
		expires := ""
		if !role.EndDateTime.IsZero() {
			expires = role.EndDateTime.Format("2006-01-02")
		}

		// Truncate long names for better display
		subscription := role.SubscriptionName
		if len(subscription) > 25 {
			subscription = subscription[:22] + "..."
		}

		roleName := role.RoleName
		if len(roleName) > 30 {
			roleName = roleName[:27] + "..."
		}

		if len(resource) > 20 {
			resource = resource[:17] + "..."
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			i+1,
			subscription,
			roleName,
			resource,
			expires,
		)
	}

	w.Flush()
	fmt.Println()

	// Prompt for selection
	var selection int
	for {
		fmt.Printf("Select a role to activate (1-%d) or 0 to exit: ", len(allRoles))
		_, err := fmt.Scanln(&selection)
		if err != nil || selection < 0 || selection > len(allRoles) {
			fmt.Println("⚠ Invalid selection. Please try again.")
			// Clear the input buffer
			var discard string
			fmt.Scanln(&discard)
			continue
		}

		if selection == 0 {
			fmt.Println("\nExiting...")
			return
		}

		break
	}

	selectedRole := allRoles[selection-1]

	fmt.Printf("\n✓ Selected: %s in %s\n\n", selectedRole.RoleName, selectedRole.SubscriptionName)

	// Find subscription ID from subscription name
	var subscriptionID string
	for _, sub := range subscriptions {
		if sub.Name == selectedRole.SubscriptionName {
			subscriptionID = sub.ID
			break
		}
	}

	// Fetch policy to get maximum allowed duration
	fmt.Println("Fetching role policy...")
	tempClient := pim.NewAzureResourcePIMClient(armToken, principalID, subscriptionID)
	maxHours, err := tempClient.GetRolePolicy(selectedRole.Scope, selectedRole.RoleDefinitionID)
	if err != nil {
		maxHours = 5 // Default fallback
	}
	fmt.Printf("✓ Maximum allowed duration: %d hours\n\n", maxHours)

	// Prompt for justification
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
			fmt.Println("⚠ Justification is required. Please try again.")
			continue
		}
		break
	}

	// Prompt for duration with dynamic default
	var durationHours string
	for {
		fmt.Printf("Enter duration in hours (default: %d, max: %d): ", maxHours, maxHours)
		fmt.Scanln(&durationHours)

		if durationHours == "" {
			durationHours = fmt.Sprintf("%d", maxHours)
			break
		}

		// Validate duration
		var hours int
		_, err := fmt.Sscanf(durationHours, "%d", &hours)
		if err != nil || hours <= 0 {
			fmt.Println("⚠ Invalid duration. Please enter a positive number.")
			continue
		}

		if hours > maxHours {
			fmt.Printf("⚠ Duration exceeds maximum allowed (%d hours). Please try again.\n", maxHours)
			continue
		}

		break
	}

	duration := fmt.Sprintf("PT%sH", durationHours)

	// Optional ticket info
	fmt.Print("Enter ticket number (optional, press Enter to skip): ")
	var ticketNumber string
	fmt.Scanln(&ticketNumber)

	ticketSystem := ""
	if ticketNumber != "" {
		fmt.Print("Enter ticket system (e.g., ServiceNow, Jira): ")
		fmt.Scanln(&ticketSystem)
	}

	// Confirm activation
	fmt.Println("\n═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println("Activation Summary:")
	fmt.Printf("  Role:          %s\n", selectedRole.RoleName)
	fmt.Printf("  Subscription:  %s\n", selectedRole.SubscriptionName)
	fmt.Printf("  Justification: %s\n", justification)
	fmt.Printf("  Duration:      %s hours\n", durationHours)
	if ticketNumber != "" {
		fmt.Printf("  Ticket:        %s (%s)\n", ticketNumber, ticketSystem)
	}
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")

	fmt.Print("\nProceed with activation? (y/n): ")
	var confirm string
	fmt.Scanln(&confirm)

	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		fmt.Println("Activation cancelled.")
		return
	}

	// Perform activation
	fmt.Println("\nActivating role...")

	req := models.ActivationRequest{
		RoleDefinitionID: selectedRole.RoleDefinitionID,
		Justification:    justification,
		Duration:         duration,
		TicketNumber:     ticketNumber,
		TicketSystem:     ticketSystem,
	}

	resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, subscriptionID)
	err = resourceClient.ActivateRole(selectedRole.Scope, req)

	if err != nil {
		fmt.Printf("\n✗ Activation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Role activated successfully!")
	fmt.Printf("  The role '%s' is now active for %s hours.\n", selectedRole.RoleName, durationHours)
	fmt.Println("\nRun 'pim status' to view your active roles.")
}

func handleActivate() {
	activateCmd := flag.NewFlagSet("activate", flag.ExitOnError)
	roleID := activateCmd.String("role-id", "", "Role definition ID to activate (required)")
	justification := activateCmd.String("justification", "", "Justification for activation (required)")
	duration := activateCmd.String("duration", "PT5H", "Activation duration (default: PT5H for 5 hours)")
	roleType := activateCmd.String("type", "azuread", "Role type: azuread or azureresource")
	scope := activateCmd.String("scope", "", "Scope for Azure resource roles (e.g., subscriptions/<sub-id>)")
	ticketNumber := activateCmd.String("ticket", "", "Ticket number (optional)")
	ticketSystem := activateCmd.String("ticket-system", "", "Ticket system (optional)")

	activateCmd.Parse(os.Args[2:])

	if *roleID == "" || *justification == "" {
		fmt.Println("Error: --role-id and --justification are required")
		activateCmd.PrintDefaults()
		os.Exit(1)
	}

	ctx, err := initializeContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	req := models.ActivationRequest{
		RoleDefinitionID: *roleID,
		Justification:    *justification,
		Duration:         *duration,
		TicketNumber:     *ticketNumber,
		TicketSystem:     *ticketSystem,
	}

	if strings.ToLower(*roleType) == "azuread" {
		adClient := pim.NewAzureADPIMClient(ctx.AccessToken, principalID)
		err = adClient.ActivateRole(req)
	} else if strings.ToLower(*roleType) == "azureresource" {
		if *scope == "" {
			*scope = fmt.Sprintf("subscriptions/%s", ctx.SubscriptionID)
		}
		armToken, err := auth.GetAzureResourceToken()
		if err != nil {
			fmt.Printf("Failed to get ARM token: %v\n", err)
			os.Exit(1)
		}
		resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, ctx.SubscriptionID)
		err = resourceClient.ActivateRole(*scope, req)
	} else {
		fmt.Printf("Invalid role type: %s (must be azuread or azureresource)\n", *roleType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Failed to activate role: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Role activated successfully!")
}

func handleDeactivate() {
	deactivateCmd := flag.NewFlagSet("deactivate", flag.ExitOnError)
	roleID := deactivateCmd.String("role-id", "", "Role definition ID to deactivate (required)")
	roleType := deactivateCmd.String("type", "azuread", "Role type: azuread or azureresource")
	scope := deactivateCmd.String("scope", "", "Scope for Azure resource roles (e.g., subscriptions/<sub-id>)")

	deactivateCmd.Parse(os.Args[2:])

	if *roleID == "" {
		fmt.Println("Error: --role-id is required")
		deactivateCmd.PrintDefaults()
		os.Exit(1)
	}

	ctx, err := initializeContext()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	principalID, err := pim.GetPrincipalID(ctx.AccessToken)
	if err != nil {
		fmt.Printf("Failed to get user principal ID: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(*roleType) == "azuread" {
		adClient := pim.NewAzureADPIMClient(ctx.AccessToken, principalID)
		err = adClient.DeactivateRole(*roleID)
	} else if strings.ToLower(*roleType) == "azureresource" {
		if *scope == "" {
			*scope = fmt.Sprintf("subscriptions/%s", ctx.SubscriptionID)
		}
		armToken, err := auth.GetAzureResourceToken()
		if err != nil {
			fmt.Printf("Failed to get ARM token: %v\n", err)
			os.Exit(1)
		}
		resourceClient := pim.NewAzureResourcePIMClient(armToken, principalID, ctx.SubscriptionID)
		err = resourceClient.DeactivateRole(*scope, *roleID)
	} else {
		fmt.Printf("Invalid role type: %s (must be azuread or azureresource)\n", *roleType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Failed to deactivate role: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Role deactivated successfully!")
}

func initializeContext() (*auth.AzureContext, error) {
	ctx, err := auth.GetAzureContext()
	if err != nil {
		return nil, err
	}

	if err := auth.ValidateContext(ctx); err != nil {
		return nil, err
	}

	return ctx, nil
}

func printRoles(roles []models.RoleAssignment) {
	if len(roles) == 0 {
		fmt.Println("No roles found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SUBSCRIPTION\tROLE NAME\tRESOURCE\tSTATUS\tEXPIRES")
	fmt.Fprintln(w, "------------\t---------\t--------\t------\t-------")

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

		// Extract resource type from scope
		resource := extractResourceFromScope(role.Scope)

		// Truncate subscription name if too long
		subscription := role.SubscriptionName
		if len(subscription) > 25 {
			subscription = subscription[:22] + "..."
		}

		// Truncate resource if too long
		if len(resource) > 30 {
			resource = resource[:27] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			subscription,
			role.RoleName,
			resource,
			role.Status,
			expiresIn,
		)
	}

	w.Flush()
	fmt.Println()
}

func extractRoleIDShort(fullID string) string {
	parts := strings.Split(fullID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullID
}

func extractResourceFromScope(scope string) string {
	// Scope format: /subscriptions/{id}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
	// Or: /subscriptions/{id}
	if scope == "" || scope == "/" {
		return "Subscription"
	}

	parts := strings.Split(scope, "/")

	// Find resource type
	for i, part := range parts {
		if part == "resourceGroups" && i+1 < len(parts) {
			return "RG: " + parts[i+1]
		}
		if part == "providers" && i+2 < len(parts) {
			// Extract last part of provider and resource type
			resourceType := parts[i+2]
			if i+3 < len(parts) {
				return resourceType + "/" + parts[i+3]
			}
			return resourceType
		}
		if part == "workspaces" && i+1 < len(parts) {
			return "Workspace: " + parts[i+1]
		}
	}

	// Default to subscription level
	return "Subscription"
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
