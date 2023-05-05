<#
.SYNOPSIS
    Deploy infrastructure required to run tests for this program.
x.EXAMPLE
    ./aadResources.ps1 `
        -AppRegistrationName poudriereakvtestsp `
        -ResourceGroupName poudriereakv-test-rg `
        -Location westus3 `
        -KeyVaultName poudriereakv-testkv `
        -KeyName poudriereakvtestkey `
        -InformationAction Continue -Verbose
    Generate test resources and output the secrets to be configured in Github Actions.
    #>
#Requires -Modules Az.Resources, Az.KeyVault, Az.Accounts

[CmdletBinding()]
param (
    # Name of the app registration to create.
    [Parameter(Mandatory)]
    [string]
    $AppRegistrationName,

    # Location in which to create resources.
    [Parameter()]
    [string]
    $Location = "westus3",

    # Name of the resource group in which to create the key vault;
    # will be created if it does not exist.
    [Parameter(Mandatory)]
    [string]
    $ResourceGroupName,

    # Name of the key vault to create; will be created if it does not exist.
    [Parameter(Mandatory)]
    [string]
    $KeyVaultName,

    # Name of the key to use; will be created if it does not exist.
    [Parameter(Mandatory)]
    [ValidateLength(1, 63)]
    [ValidatePattern("^[0-9a-zA-Z-]+$")]
    [string]
    $KeyName
)

$ctx = Get-AzContext -ErrorAction SilentlyContinue
if ($null -eq $ctx) {
    Write-Error "Please login to Azure using Connect-AzAccount."
    return
}

$app = Get-AzADApplication `
    -DisplayName $AppRegistrationName `
    -ErrorAction SilentlyContinue
if ($null -eq $app) {
    Write-Information "App registration ${AppRegistrationName} not found; creating."
    $app = New-AzAdApplication `
        -DisplayName $AppRegistrationName `
        -AvailableToOtherTenants $false `
        -SignInAudience AzureADMyOrg `
        -ErrorAction Stop
}

# Create a client secret for Github Actions to use.
$clientSecret = $app |
New-AzADAppCredential `
    -ErrorAction Stop

# Get the resource group; create if necessary.
$rg = Get-AzResourceGroup `
    -Name $ResourceGroupName `
    -ErrorAction SilentlyContinue
if ($null -eq $rg) {
    Write-Information "Resource group ${ResourceGroupName} not found; creating."
    $rg = New-AzResourceGroup `
        -Name $ResourceGroupName `
        -Location $Location `
        -ErrorAction Stop
}

# Get or create the key vault.
$kv = Get-AzKeyVault `
    -VaultName $KeyVaultName `
    -ResourceGroupName $ResourceGroupName `
    -ErrorAction SilentlyContinue
if ($null -eq $kv) {
    Write-Information "Key vault ${KeyVaultName} not found; creating."
    $kv = New-AzKeyVault `
        -VaultName $KeyVaultName `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -EnableRbacAuthorization `
        -ErrorAction Stop
}

# Grant the service principal access to the key vault.
$sp = Get-AzADServicePrincipal `
    -ApplicationId $app.AppId `
    -ErrorAction SilentlyContinue

if ($null -eq $sp) {
    Write-Information "Service principal for app registration ${AppRegistrationName} not found; creating."
    $sp = New-AzADServicePrincipal `
        -ApplicationId $app.AppId `
        -ErrorAction Stop
}

# Grant the service principal access to the key vault if it doesn't already have it.
$roleAssignment = Get-AzRoleAssignment `
    -ObjectId $sp.Id `
    -RoleDefinitionName "Key Vault Crypto User" `
    -Scope $kv.ResourceId `
    -ErrorAction SilentlyContinue

if ($null -eq $roleAssignment) {
    Write-Information "Granting application $($app.DisplayName) access to key vault ${KeyVaultName}."
    New-AzRoleAssignment `
        -ApplicationId $app.AppId `
        -RoleDefinitionName "Key Vault Crypto User" `
        -Scope $kv.ResourceId `
        -ErrorAction Stop | Out-Null
}

# Get the current user's object ID.
$currentUser = (Get-AzADUser `
    -SignedIn `
    -ErrorAction Stop).Id

# Grant the calling user access to the key vault if they don't already have it.
$roleAssignment = Get-AzRoleAssignment `
    -ObjectId $currentUser `
    -Scope $kv.ResourceId `
    -RoleDefinitionName "Key Vault Crypto Officer" `
    -ErrorAction SilentlyContinue

if ($null -eq $roleAssignment) {
    Write-Information "Granting user $($ctx.Account.Id) access to key vault ${KeyVaultName}."
    New-AzRoleAssignment `
        -ObjectId $currentUser `
        -RoleDefinitionName "Key Vault Crypto Officer" `
        -Scope $kv.ResourceId `
        -ErrorAction Stop | Out-Null
    Write-Information "Sleeping for 60 seconds to allow role assignment to propagate."
    Start-Sleep -Seconds 60
}

# Create the key if it doesn't exist.
$key = Get-AzKeyVaultKey `
    -VaultName $kv.VaultName `
    -Name $KeyName `
    -ErrorAction SilentlyContinue

if ($null -eq $key) {
    Write-Information "Key ${KeyName} not found; creating."
    $key = Add-AzKeyVaultKey `
        -VaultName $kv.VaultName `
        -Name $KeyName `
        -Destination Software `
        -ErrorAction Stop
}

# Output the parameters to be configured in Github Actions.
Write-Output "AZURE_CLIENT_ID=$($app.AppId)"
Write-Output "AZURE_CLIENT_SECRET=$($clientSecret.SecretText)"
Write-Output "AZURE_TENANT_ID=$($ctx.Tenant.Id)"
Write-Output "TEST_KEY=$($key.Key.kid)"