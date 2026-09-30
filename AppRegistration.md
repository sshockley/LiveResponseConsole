# App Registration
The WindowsDefenderATP resource app ID is always `fc780465-2017-40d4-a0c5-307022471b92` every tenant.  Running these commands needs a privileged role (Privileged Role Administrator or Global Administrator) for the consent step.

## Azure CLI

```powershell
$mdeApi   = 'fc780465-2017-40d4-a0c5-307022471b92'
$tenantId = '<your tenant id>'
$roles    = 'Machine.LiveResponse','Machine.ReadWrite.All','Library.Manage'

# az cloud set --name AzureUSGovernment     # gov clouds only, before login
az login --tenant $tenantId --allow-no-subscriptions

# The MDE resource SP must exist before roles can be assigned against it.
# A missing SP is what produces AADSTS650052 later.
az ad sp show --id $mdeApi --query id -o tsv 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { az ad sp create --id $mdeApi | Out-Null }

$appId = az ad app create `
    --display-name "MDE Live Response (console)" `
    --sign-in-audience AzureADMyOrg `
    --query appId -o tsv

az ad sp create --id $appId | Out-Null

$spOid    = az ad sp show --id $appId  --query id -o tsv
$mdeSpOid = az ad sp show --id $mdeApi --query id -o tsv

# Resolve role IDs by name, filtered to application roles
$roleIds = @{}
foreach ($r in $roles) {
    $id = az ad sp show --id $mdeApi `
        --query "appRoles[?value=='$r' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv
    if (-not $id) { throw "App role not found on WindowsDefenderATP: $r" }
    $roleIds[$r] = $id
}

# Declare the permissions on the app registration
# "is needed to make the change effective" warnings are okay here
foreach ($r in $roles) {
    az ad app permission add --id $appId --api $mdeApi --api-permissions "$($roleIds[$r])=Role"
}

# Admin consent
$bodyFile = [IO.Path]::GetTempFileName()
foreach ($r in $roles) {
    @{ principalId = $spOid; resourceId = $mdeSpOid; appRoleId = $roleIds[$r] } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $bodyFile -Encoding ascii

    az rest --method post `
        --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignments" `
        --headers "Content-Type=application/json" `
        --body "@$bodyFile"
}
Remove-Item -LiteralPath $bodyFile

"ClientId: $appId"

# Verify. Application permissions are appRoleAssignments.
# "az ad app permission list-grants" shows delegated oauth2PermissionGrants only
# and looks empty even when consent succeeded.
(az rest --method get `
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/appRoleAssignments" |
    ConvertFrom-Json).value | Select-Object appRoleId, resourceDisplayName, createdDateTime
```

## Microsoft Graph PowerShell

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser

$mdeApiAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$roleNames   = 'Machine.LiveResponse','Machine.ReadWrite.All','Library.Manage'

Connect-MgGraph -TenantId $tid `
    -Scopes Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All
# add -Environment USGov for GCC High, USGovDoD for DoD

$mdeSp = Get-MgServicePrincipal -Filter "appId eq '$mdeApiAppId'"
if (-not $mdeSp) { $mdeSp = New-MgServicePrincipal -AppId $mdeApiAppId }

$resourceAccess = foreach ($r in $roleNames) {
    @{ Id = ($mdeSp.AppRoles | Where-Object Value -EQ $r).Id; Type = 'Role' }
}

$app = New-MgApplication `
    -DisplayName 'MDE Live Response (console)' `
    -SignInAudience AzureADMyOrg `
    -RequiredResourceAccess @(@{
        ResourceAppId  = $mdeApiAppId
        ResourceAccess = @($resourceAccess)
    })

$sp = New-MgServicePrincipal -AppId $app.AppId

# Admin consent is one app role assignment per permission
foreach ($ra in $resourceAccess) {
    New-MgServicePrincipalAppRoleAssignment `
        -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
        -ResourceId $mdeSp.Id -AppRoleId $ra.Id | Out-Null
}

"ClientId: $($app.AppId)"
"ObjectId: $($app.Id)"
```

Notes for all methods:

- Remove `Library.Manage` role if you are not using the `library` verbs.
- Role assignments can take a minute to show up in tokens. A 403 on the first run that clears by itself is usually propagation.
- `New-MgApplication` publishes no credential. The app cannot authenticate until you attach the certificate below.


## Delegated sign-in (`-UseDeviceCode`)

Everything above configures **application** permissions, which is all the certificate and
client-secret flows need. `-UseDeviceCode` signs in as a user instead, and the app
registration needs two more things:

1. **Allow public client flows** must be enabled. Without it the token request fails with
   `AADSTS7000218: The request body must contain the following parameter: 'client_assertion' or 'client_secret'`.

   ```powershell
   # Azure CLI
   az ad app update --id $appId --is-fallback-public-client true

   # Microsoft Graph PowerShell
   Update-MgApplication -ApplicationId $app.Id -IsFallbackPublicClient
   ```

2. **Delegated** counterparts of the permissions, admin-consented. Application roles are
   not used in a delegated token, so add the `Scope`-type permissions
   `Machine.LiveResponse`, `Machine.ReadWrite` and `Library.Manage` on the
   WindowsDefenderATP API.

   ```powershell
   # Azure CLI: resolve the delegated (oauth2PermissionScopes) IDs and add them as Scope
   $scopes = 'Machine.LiveResponse','Machine.ReadWrite','Library.Manage'
   foreach ($s in $scopes) {
       $id = az ad sp show --id $mdeApi `
           --query "oauth2PermissionScopes[?value=='$s'].id | [0]" -o tsv
       if (-not $id) { throw "Delegated scope not found on WindowsDefenderATP: $s" }
       az ad app permission add --id $appId --api $mdeApi --api-permissions "$id=Scope"
   }
   az ad app permission admin-consent --id $appId
   ```

   ```powershell
   # Microsoft Graph PowerShell: grant the delegated scopes tenant-wide
   $scopes = 'Machine.LiveResponse','Machine.ReadWrite','Library.Manage'
   New-MgOauth2PermissionGrant -BodyParameter @{
       clientId    = $sp.Id
       consentType = 'AllPrincipals'
       resourceId  = $mdeSp.Id
       scope       = ($scopes -join ' ')
   } | Out-Null
   ```

Notes on using delegated permissions:

- The signed-in analyst also needs an MDE RBAC role that permits Live Response on the
  target device group. The app's permissions alone are not enough.
- Machine actions are attributed to the **user**, not the app registration, in the Action
  center and in `actions` output. That is often the point of choosing this flow.
