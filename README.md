# PIM Manager

A command-line tool for managing Microsoft Azure Privileged Identity Management (PIM) role activations.

## Features

- ✅ **Azure Resource Roles** - Fully supported (Contributor, Owner, etc.)
  - List eligible and active roles
  - Activate/deactivate with justification
  - Works with Azure CLI authentication
- ⚠️ **Azure AD Roles** - Limited support
  - Azure CLI tokens lack required PIM permissions
  - Use Azure Portal for Azure AD role management
- Uses Azure CLI authentication (no credentials stored)
- Validates subscription context before operations

## Prerequisites

- Go 1.19 or later
- Azure CLI installed and configured
- Valid Azure subscription with PIM-enabled roles

## Installation

### Option 1: Install using `go install` (Recommended)

```bash
# Install directly from GitHub
go install github.com/anasmohana/pim/cmd/pim@latest

# The binary will be installed to $GOPATH/bin (usually ~/go/bin)
# Make sure this directory is in your PATH
```

### Option 2: Build from source

```bash
# Clone the repository
git clone https://github.com/anasmohana/pim.git
cd pim

# Build the binary
go build -o pim ./cmd/pim

# Optional: Move to a directory in your PATH
sudo mv pim /usr/local/bin/
```

### Option 3: Download pre-built binaries (No Go required)

1. Go to the [Releases page](https://github.com/anasmohana/pim/releases)
2. Download the appropriate binary for your system:
   - **macOS (Intel)**: `pim_*_darwin_amd64.tar.gz`
   - **macOS (Apple Silicon)**: `pim_*_darwin_arm64.tar.gz`
   - **Linux (64-bit)**: `pim_*_linux_amd64.tar.gz`
   - **Windows (64-bit)**: `pim_*_windows_amd64.zip`
3. Extract and move to your PATH:
   ```bash
   # macOS/Linux
   tar -xzf pim_*_*.tar.gz
   sudo mv pim /usr/local/bin/

   # Windows: Extract the zip and add to your PATH
   ```

## Usage

### Authentication

The tool uses Azure CLI for authentication. Before using the tool, ensure you're logged in:

```bash
az login
```

The tool will:
1. Check for valid Azure CLI tokens
2. Display your current tenant
3. Check PIM roles across ALL your subscriptions

### Quick Start - Interactive Mode (Recommended)

Simply run the tool without any commands for an interactive experience:

```bash
./pim
```

This will:
1. Show all your eligible PIM roles across all subscriptions
2. Let you select a role by number
3. Prompt for justification and duration
4. Activate the role automatically

**Example Interactive Session:**
```
╔══════════════════════════════════════════╗
║   PIM Manager - Interactive Mode        ║
╚══════════════════════════════════════════╝

✓ Found 12 eligible role(s)

#   SUBSCRIPTION              ROLE NAME                  RESOURCE       EXPIRES
-   ------------              ---------                  --------       -------
1   Production-App            Contributor                Subscription   2026-12-01
2   Production-Database       Owner                      Subscription   2026-10-01
3   Staging-Environment       Contributor                Subscription   2026-08-15
4   Development-Resources     Reader                     Subscription   2026-04-27
5   Shared-Services           Key Vault Administrator    Subscription
...

Select a role to activate (1-12) or 0 to exit: 1

✓ Selected: Contributor in Production-App

Fetching role policy...
✓ Maximum allowed duration: 5 hours

Enter justification (reason for activation): Deploy critical security patch
Enter duration in hours (default: 5, max: 5): 4

✓ Role activated successfully!
  The role 'Contributor' is now active for 4 hours.
```

### Smart Features

#### 🔍 Dynamic Policy Detection
The tool automatically fetches the PIM policy for each role to determine:
- **Maximum allowed duration** - No more "ExpirationRule" errors!
- **Default duration** - Uses the policy maximum as the default
- **Input validation** - Prevents you from requesting more time than allowed

Each PIM role can have different policies (5 hours, 8 hours, etc.). The tool detects this automatically.

#### 🌍 Multi-Subscription Support
Automatically checks **all** your Azure subscriptions for eligible roles:
- Filters out cross-tenant subscriptions
- Shows subscription name with each role
- Activates in the correct subscription automatically

### Commands

#### List Eligible Roles

List all roles available for activation:

```bash
./pim list
```

This displays Azure Resource roles across all your subscriptions.

#### Check Active Assignments

View currently active role assignments:

```bash
./pim status
```

#### Activate a Role

Activate an eligible PIM role:

```bash
# Azure AD role
./pim activate \
  --role-id <role-definition-id> \
  --justification "Emergency production fix" \
  --duration PT8H \
  --type azuread

# Azure Resource role
./pim activate \
  --role-id <role-definition-id> \
  --justification "Deploy new feature" \
  --duration PT4H \
  --type azureresource \
  --scope "subscriptions/<subscription-id>"
```

**Parameters:**
- `--role-id`: The role definition ID (get from `list` command)
- `--justification`: Required reason for activation
- `--duration`: Activation duration (default: PT5H = 5 hours)
  - Format: ISO 8601 duration (PT1H = 1 hour, PT30M = 30 minutes)
  - **Note**: Maximum duration is determined by your PIM policy (typically 5-8 hours)
- `--type`: Role type - `azuread` or `azureresource` (default: azuread)
- `--scope`: Scope for Azure resource roles (optional, defaults to current subscription)
- `--ticket`: Ticket number (optional)
- `--ticket-system`: Ticket system name (optional)

#### Deactivate a Role

Deactivate an active PIM role:

```bash
# Azure AD role
./pim deactivate --role-id <role-definition-id> --type azuread

# Azure Resource role
./pim deactivate --role-id <role-definition-id> --type azureresource
```

## Examples

### Interactive mode (Easiest - Recommended)
```bash
# Just run without arguments
./pim

# Follow the prompts to:
# 1. See all eligible roles
# 2. Select by number
# 3. Enter justification
# 4. Activate!
```

### List all eligible roles
```bash
./pim list
```

### Check active assignments
```bash
./pim status
```

### Manual activation (Advanced)
```bash
# Activate Contributor role on a subscription
./pim activate \
  --role-id b24988ac-6180-42a0-ab88-20f7382dd24c \
  --justification "Deploy infrastructure changes" \
  --duration PT4H \
  --type azureresource \
  --scope "subscriptions/<subscription-id>"
```

### Deactivate a role
```bash
./pim deactivate \
  --role-id <role-definition-id> \
  --type azureresource
```

## Project Structure

```
pim/
├── cmd/pim/           # CLI application entry point
│   └── main.go
├── internal/
│   ├── auth/          # Azure CLI authentication
│   │   └── azcli.go
│   └── pim/           # PIM client implementations
│       ├── azuread.go
│       └── azureresource.go
├── pkg/models/        # Data models
│   └── role.go
├── go.mod
└── README.md
```

## How It Works

1. **Authentication**: Uses `az account get-access-token` to retrieve tokens for Microsoft Graph and Azure Resource Manager APIs
2. **Token Validation**: Checks token expiration and prompts user to refresh if needed
3. **Context Validation**: Displays current tenant and subscription, asks for confirmation
4. **API Calls**: Makes authenticated REST API calls to:
   - Microsoft Graph API (for Azure AD PIM)
   - Azure Resource Manager API (for Azure Resource PIM)
5. **Role Management**: Handles activation, deactivation, and listing of PIM roles

## Troubleshooting

### "failed to get Azure account info"
- Run `az login` to authenticate with Azure CLI

### "access token has expired"
- Run `az login` again to refresh your tokens

### "PermissionScopeNotGranted" or Azure AD PIM returns 403
**This is expected behavior** - Azure CLI tokens don't include the `RoleManagement.Read.Directory` scope required for Azure AD PIM.

**Solution:**
- ✅ **Azure Resource PIM works perfectly** - use it for subscription roles (Contributor, Owner, etc.)
- For Azure AD directory roles, use:
  - [Azure Portal PIM](https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles)
  - PowerShell with `Connect-AzureAD`
  - See [AZURE_AD_PIM.md](AZURE_AD_PIM.md) for detailed workarounds

### "API request failed with status 403" (Azure Resource roles)
- Ensure you have PIM roles assigned for the subscription
- Check that PIM is enabled for your subscription
- Verify you're in the correct subscription with `az account show`

### "please run 'az account set'"
- Switch to the correct subscription using `az account set --subscription <subscription-id>`

## API Permissions

The tool requires the following:
- User must be eligible for PIM roles
- Access to Microsoft Graph API (via Azure CLI)
- Access to Azure Resource Manager API (via Azure CLI)

## License

MIT
