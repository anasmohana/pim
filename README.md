# PIM Manager

A command-line tool for managing Microsoft Azure Privileged Identity Management (PIM) role activations, inspired by [pim-activate](https://github.com/dnb/pim-activate).

## Features

- ✅ **Azure AD Groups** - Fully supported
- ✅ **Azure Resource Roles** - Fully supported (Contributor, Owner, etc.)
- ✅ **Microsoft Entra Roles** - Fully supported
- ✅ **MFA/ACRS Authentication** - Auto-detects and handles MFA challenges
- ✅ **Interactive UI** - Select roles interactively or activate by name
- ✅ **Smart Filtering** - Filters out already-active roles from eligible list
- ✅ **Direct Activation** - `pim -g my-group-name` for quick activation
- ✅ **Non-Interactive Mode** - Pass justification and duration as flags for scripting/automation
- ✅ **Deactivation Support** - Full deactivation support for all PIM types
- ✅ **Policy-Aware** - Auto-detects maximum allowed duration per role

## Prerequisites

- Go 1.19 or later (for building from source)
- Azure CLI installed and configured (`az login`)
- Valid Azure subscription with PIM-enabled roles

## Installation

### Homebrew (Recommended for macOS)

```bash
# Add the tap
brew tap anasmohana/pim https://github.com/anasmohana/pim.git

# Install
brew install pim

# That's it! The tool is now available as 'pim'
```

**Update later:**
```bash
brew upgrade pim
```

### Build from Source (All Platforms)

```bash
# Clone the repository
git clone https://github.com/anasmohana/pim.git
cd pim

# Build the binary
go build -o pim ./cmd/pim

# Optional: Move to a directory in your PATH
# macOS/Linux:
sudo mv pim /usr/local/bin/

# Windows: Add to your PATH or use directly
```

### Download Pre-built Binaries (GitHub Releases)

For Windows users or those who prefer pre-built binaries:

1. Go to the [Releases page](https://github.com/anasmohana/pim/releases)
2. Download the appropriate binary for your system
3. Extract and use directly (no code signing needed for internal tools)

## Usage

### Authentication

The tool uses Azure CLI for authentication. Before using the tool, ensure you're logged in:

```bash
az login
```

### Quick Examples

```bash
# Interactive mode - select PIM type, then select role
pim

# Activate an Azure AD Group directly
pim -g aws-pim-access

# Activate non-interactively with justification and duration
pim -g my-group -j "I have work to do" -d 8

# Activate an Azure Resource role
pim -r

# Activate a Microsoft Entra Role
pim -e

# Deactivate a Group role
pim d -g

# Deactivate a Resource role
pim deactivate -r
```

### Command-Line Options

```
Usage: pim [OPTIONS] [ACTION]

Options:
  -h, --help                    Show this help message
  -g, --group [NAME]            PIM type: Azure AD Groups
  -r, --resource [NAME]         PIM type: Azure Resources
  -e, --entra [NAME]            PIM type: Microsoft Entra Roles
  -j, --justification TEXT      Justification for activation (skips prompt)
  -d, --duration HOURS          Duration in hours (skips prompt)

Actions:
  deactivate, d       Deactivate an active role

Examples:
  pim                                            # Interactive mode
  pim -g                                         # List and activate Azure AD Groups
  pim -g my-group-name                           # Activate specific group by name
  pim -g my-group -j "I have work to do" -d 8   # Fully non-interactive activation
  pim -r                                         # List and activate Azure Resources
  pim -e                                         # List and activate Entra Roles
  pim d -g                                       # Deactivate a group role
  pim deactivate -r                              # Deactivate a resource role
```

### Interactive Mode

Simply run `pim` without any arguments for an interactive experience:

```bash
./pim
```

The tool will:
1. Prompt you to select a PIM type (Groups, Resources, or Entra Roles)
2. Show all eligible roles (excluding already-active ones)
3. Let you select a role to activate
4. Prompt for justification (defaults to "Routine administrative access")
5. Prompt for duration (defaults to maximum allowed)
6. Activate the role automatically

### Direct Activation by Name

Activate a role directly by specifying its name:

```bash
# Activate a specific group
pim -g my-pim-group

# Activate a specific resource role (partial match supported)
pim -r contributor

# Activate a specific Entra role
pim -e "Global Administrator"
```

### Non-Interactive Mode

Pass `-j` and `-d` to skip all prompts — useful for scripting and automation:

```bash
# Fully non-interactive activation
pim -g my-group -j "Deployment work" -d 8

# Works with all PIM types
pim -r contributor -j "Infra change" -d 2
pim -e "Global Administrator" -j "Emergency access" -d 1
```

If either flag is omitted, the tool falls back to an interactive prompt for that field. If `-d` exceeds the role's policy maximum, it is automatically capped.

### Deactivation

Deactivate active roles:

```bash
# Interactive deactivation - select PIM type, then select role
pim d

# Deactivate a specific group
pim d -g my-pim-group

# Interactive deactivation of resource roles
pim deactivate -r
```

### MFA/ACRS Authentication

The tool automatically detects when MFA or Conditional Access authentication is required:

1. When MFA is needed, the tool will automatically open your browser
2. Complete the MFA challenge in the browser
3. The tool will detect successful authentication and continue
4. Your role will be activated automatically

This mirrors the behavior of the popular `pim-activate` bash script.

## How It Works

1. **Authentication**: Uses `az account get-access-token` to retrieve tokens for the MS PIM API
2. **Token Validation**: Checks token expiration and prompts user to refresh if needed
3. **PIM API**: Makes authenticated REST API calls to `https://api.azrbac.mspim.azure.com`
4. **Policy Detection**: Fetches role policies to determine maximum allowed duration
5. **MFA Handling**: Detects MFA challenges, extracts claims, and re-authenticates
6. **Smart Filtering**: Filters out already-active roles from the eligible list

## Supported PIM Types

### 1. Azure AD Groups (`-g`)
Activate membership in Azure AD PIM-enabled groups. Useful for access to:
- AWS accounts via SAML
- GCP projects via SAML
- Third-party applications
- Network resources

### 2. Azure Resources (`-r`)
Activate Azure Resource roles at subscription, resource group, or resource level:
- Contributor
- Owner
- Reader
- Key Vault Administrator
- Custom roles

### 3. Microsoft Entra Roles (`-e`)
Activate directory-level roles in Microsoft Entra ID:
- Global Administrator
- User Administrator
- Security Administrator
- Application Administrator
- Custom roles

## Troubleshooting

### "failed to get Azure account info"
- Run `az login` to authenticate with Azure CLI

### "access token has expired"
- Run `az login` again to refresh your tokens

### "MFA/ACRS authentication required"
- The tool will automatically open your browser for MFA
- Complete the authentication challenge
- The tool will automatically continue

### "failed to get PIM token"
- Ensure you have access to PIM-enabled roles
- Try running `az login` again
- Verify your tenant has PIM configured

### "'role-name' not found in eligible roles"
- Check that the role name is correct (case-insensitive partial match supported)
- Verify the role is eligible (not already active)
- Ensure you have PIM access to that role

### "ActiveDurationTooShort"
Roles must be active for at least 5 minutes before deactivation. This is a PIM policy restriction.

## Differences from Bash Script

This Go implementation provides several advantages over the original bash script:

| Feature | Bash Script | Go Tool |
|---------|-------------|---------|
| Installation | Requires `gum`, `jq`, `az` | Single binary, only requires `az` |
| Platform | macOS/Linux only | Cross-platform (Windows, macOS, Linux) |
| Performance | Multiple process spawns | Native performance |
| Error Handling | Basic | Comprehensive with retry logic |
| Distribution | Homebrew tap | GitHub releases + go install |
| Codebase | ~400 lines bash | Clean Go architecture |

However, both tools share the same core functionality and user experience!

## Project Structure

```
pim/
├── cmd/pim/              # CLI application entry point
│   └── main.go
├── internal/
│   ├── auth/             # Azure CLI authentication
│   │   └── azcli.go
│   └── pim/              # PIM client implementations
│       └── unified.go    # Unified client for all PIM types
├── pkg/models/           # Data models
│   └── role.go
├── go.mod
└── README.md
```

## API Permissions

The tool requires:
- User must be eligible for PIM roles
- Access to MS PIM API (via Azure CLI tokens)
- MFA enrollment (if required by your organization)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Credits

Inspired by the excellent [pim-activate](https://github.com/dnb/pim-activate) bash script.
