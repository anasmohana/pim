# Azure AD PIM Support and Permissions

## Current Status

**Azure Resource PIM**: ✅ Fully supported
**Azure AD PIM**: ⚠️ Limited support due to permission constraints

## The Permission Issue

### Problem

Azure CLI tokens (`az account get-access-token`) have **fixed permission scopes** that do not include the specific scopes required for Azure AD PIM operations via the Microsoft Graph API.

**Your current token scopes:**
- `Directory.AccessAsUser.All`
- `User.Read.All`
- `Group.ReadWrite.All`
- etc.

**Required for Azure AD PIM:**
- `RoleManagement.Read.Directory` OR
- `RoleEligibilitySchedule.Read.Directory` OR
- `RoleManagement.Read.All`

These PIM-specific scopes are **NOT included** in standard Azure CLI tokens and cannot be added via `az login`.

### Why Azure Resource PIM Works

Azure Resource PIM (for subscription/resource roles like Contributor, Owner, etc.) uses the **Azure Resource Manager API** (`https://management.azure.com`), which authenticates using your existing Azure subscription permissions. No special Graph API scopes are needed.

## Workarounds

### Option 1: Use Azure Portal (Recommended for Azure AD Roles)

For Azure AD directory roles (Global Administrator, Security Administrator, etc.):

1. Go to [Azure Portal PIM](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles)
2. Navigate to **Azure AD Roles** > **My roles**
3. Activate roles manually through the portal

### Option 2: Use PowerShell with Connect-AzureAD

If you need CLI access to Azure AD PIM:

```powershell
# Install the module
Install-Module -Name AzureADPreview

# Connect with proper scopes
Connect-AzureAD

# List eligible roles
Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -Filter "subjectId eq '<your-object-id>'"
```

### Option 3: Create an App Registration (For Automation)

If you need programmatic access:

1. **Create App Registration** in Azure Portal
2. **Add API Permissions**:
   - Microsoft Graph > Application permissions:
     - `RoleManagement.Read.Directory`
     - `RoleManagement.ReadWrite.Directory` (if activating)
3. **Grant admin consent** for these permissions
4. **Create client secret**
5. Update the tool to use client credential flow:

```bash
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<secret>"
export AZURE_TENANT_ID="<tenant-id>"
```

### Option 4: REST API with Browser Token

For one-time use, you can extract a token from your browser:

1. Open Azure Portal and authenticate
2. Open browser DevTools (F12) > Network tab
3. Activate a PIM role manually
4. Find the PIM API call and copy the Authorization header
5. Use that token temporarily with the tool

**Note**: Browser tokens expire quickly (typically 1 hour).

## Technical Details

### Microsoft Graph API Endpoints Used

**Eligible Roles:**
```
GET https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances
```

**Active Roles:**
```
GET https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances
```

**Required Permissions:**
- Delegated: `RoleManagement.Read.Directory`
- Application: `RoleManagement.Read.All`

### Azure Resource Manager API Endpoints Used (Working)

**Eligible Roles:**
```
GET https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances
```

**Required Permissions:**
- Your existing subscription role (e.g., Reader or higher)

## Comparison: Azure AD vs Azure Resource Roles

| Feature | Azure AD Roles | Azure Resource Roles |
|---------|----------------|---------------------|
| **Examples** | Global Admin, Security Admin | Contributor, Owner |
| **Scope** | Tenant/Directory | Subscription/Resource Group |
| **API** | Microsoft Graph | Azure Resource Manager |
| **CLI Support** | ❌ Limited (permission issue) | ✅ Full support |
| **Token Required** | Graph with PIM scopes | ARM with subscription access |

## Recommendations

1. **For most users**: Use this tool for **Azure Resource PIM** (subscription roles) - it works perfectly
2. **For Azure AD roles**: Use Azure Portal or PowerShell
3. **For automation**: Create an app registration with proper permissions
4. **Consider**: Most PIM usage is for Azure Resource roles anyway (Contributor, Owner on subscriptions)

## Future Improvements

Possible enhancements to add Azure AD PIM support:

1. **Device Code Flow**: Implement interactive OAuth flow with proper scopes
2. **Service Principal Support**: Add option to use app registration credentials
3. **Cached Token**: Support for providing a pre-authenticated token
4. **Browser-based Auth**: Launch browser for interactive consent

## Questions?

If you need help with:
- Setting up app registrations
- PowerShell alternatives
- Understanding the difference between Azure AD and Azure Resource roles

File an issue or check the [Microsoft PIM documentation](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/).
