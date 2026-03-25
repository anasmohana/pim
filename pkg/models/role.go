package models

import "time"

// RoleType represents the type of PIM role
type RoleType string

const (
	RoleTypeAzureAD       RoleType = "azuread"
	RoleTypeAzureResource RoleType = "azureresource"
)

// RoleAssignment represents a PIM role assignment
type RoleAssignment struct {
	ID                string    `json:"id"`
	RoleDefinitionID  string    `json:"roleDefinitionId"`
	RoleName          string    `json:"roleName"`
	PrincipalID       string    `json:"principalId"`
	Scope             string    `json:"scope"`
	SubscriptionName  string    `json:"subscriptionName,omitempty"`
	ResourceName      string    `json:"resourceName,omitempty"`
	Status            string    `json:"status"`
	Type              RoleType  `json:"type"`
	StartDateTime     time.Time `json:"startDateTime"`
	EndDateTime       time.Time `json:"endDateTime"`
	IsEligible        bool      `json:"isEligible"`
	Justification     string    `json:"justification,omitempty"`
}

// ActivationRequest represents a request to activate a PIM role
type ActivationRequest struct {
	RoleDefinitionID string
	Justification    string
	Duration         string // e.g., "PT5H" for 5 hours, "PT8H" for 8 hours
	TicketNumber     string
	TicketSystem     string
}
