<#
.SYNOPSIS
    Entra ID: userenként MFA kikényszerítés (enforcement), regisztrált MFA módszerek és azok erőssége.

.DESCRIPTION
    Microsoft Graph PowerShell SDK-t használ.
    Kikényszerítés forrásai: per-user MFA állapot (beta), Security Defaults, Conditional Access.
    Módszerek: alapmódban a userRegistrationDetails riport, -Detailed módban userenkénti lekérdezés
    (telefonszám, e-mail cím, Authenticator eszköznév, FIDO2 kulcs is látszik).

.PARAMETER TenantId
    Tenant ID vagy domain (opcionális).

.PARAMETER OutputPath
    CSV kimenet helye.

.PARAMETER Detailed
    Userenkénti részletes módszer-lekérdezés (lassabb, P1 licenc nélkül is működik).

.PARAMETER IncludeGuests
    Vendég (Guest) userek bevonása.

.PARAMETER SkipPerUserState
    A régi per-user MFA állapot (beta végpont) kihagyása, nagy tenantnál gyorsít.

.EXAMPLE
    .\Get-EntraMfaReport.ps1
    .\Get-EntraMfaReport.ps1 -TenantId contoso.onmicrosoft.com -Detailed -IncludeGuests
    .\Get-EntraMfaReport.ps1 -SkipPerUserState
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = ".\Entra_MFA_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').csv",
    [switch]$Detailed,
    [switch]$IncludeGuests,
    [switch]$SkipPerUserState
)

# --- Modulok ---------------------------------------------------------------
$requiredModules = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Reports',
                   'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Groups',
                   'Microsoft.Graph.Identity.DirectoryManagement'
foreach ($m in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "Hiányzó modul: $m - telepítés..." -ForegroundColor Yellow
        Install-Module $m -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $m -ErrorAction Stop
}

# --- Bejelentkezés ---------------------------------------------------------
$scopes = 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All',
          'Reports.Read.All', 'Policy.Read.All', 'Directory.Read.All'
$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$ctx = Get-MgContext
Write-Host "Csatlakozva. Tenant: $($ctx.TenantId)  Account: $($ctx.Account)" -ForegroundColor Green

# --- Userek ----------------------------------------------------------------
Write-Host "Userek lekérdezése..." -ForegroundColor Cyan
$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled, UserType
if (-not $IncludeGuests) { $users = $users | Where-Object { $_.UserType -ne 'Guest' } }
Write-Host "Talált userek: $($users.Count)"

# --- Security Defaults -----------------------------------------------------
$securityDefaults = $false
try {
    $securityDefaults = [bool](Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy).IsEnabled
}
catch { Write-Warning "Security Defaults állapot nem kérdezhető le: $($_.Exception.Message)" }
Write-Host "Security Defaults: $securityDefaults"

# --- Conditional Access: MFA-t követelő szabályok --------------------------
Write-Host "Conditional Access szabályok lekérdezése..." -ForegroundColor Cyan
$caEnforced   = @()
$caReportOnly = @()
try {
    $allCa = Get-MgIdentityConditionalAccessPolicy -All
    $mfaCa = $allCa | Where-Object {
        $_.GrantControls -and (
            $_.GrantControls.BuiltInControls -contains 'mfa' -or
            $_.GrantControls.AuthenticationStrength.Id )
    }
    $caEnforced   = @($mfaCa | Where-Object { $_.State -eq 'enabled' })
    $caReportOnly = @($mfaCa | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
}
catch { Write-Warning "CA szabályok nem kérdezhetők le (Policy.Read.All kell): $($_.Exception.Message)" }
Write-Host "MFA-t követelő aktív CA szabály: $($caEnforced.Count), report-only: $($caReportOnly.Count)"

# --- Csoport- és szerepkör-tagságok cache ---------------------------------
$groupCache = @{}
function Get-GroupMemberSet([string]$GroupId) {
    if (-not $groupCache.ContainsKey($GroupId)) {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        try { Get-MgGroupTransitiveMember -GroupId $GroupId -All | ForEach-Object { [void]$set.Add($_.Id) } } catch {}
        $groupCache[$GroupId] = $set
    }
    $groupCache[$GroupId]
}

$roleCache = @{}
try {
    Get-MgDirectoryRole -All | ForEach-Object {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        try { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object { [void]$set.Add($_.Id) } } catch {}
        $roleCache[$_.RoleTemplateId] = $set
    }
}
catch { Write-Warning "Szerepkör tagságok nem kérdezhetők le: $($_.Exception.Message)" }

function Test-UserInPolicy([string]$UserId, $Policy) {
    $cu = $Policy.Conditions.Users
    $matchSide = {
        param($userList, $groupList, $roleList)
        if ($userList -contains 'All' -or $userList -contains $UserId) { return $true }
        foreach ($g in $groupList) { if ((Get-GroupMemberSet $g).Contains($UserId)) { return $true } }
        foreach ($r in $roleList)  { if ($roleCache.ContainsKey($r) -and $roleCache[$r].Contains($UserId)) { return $true } }
        return $false
    }
    $included = & $matchSide $cu.IncludeUsers $cu.IncludeGroups $cu.IncludeRoles
    if (-not $included) { return $false }
    $excluded = & $matchSide $cu.ExcludeUsers $cu.ExcludeGroups $cu.ExcludeRoles
    return (-not $excluded)
}

# --- Per-user MFA állapot (beta) -------------------------------------------
function Get-PerUserMfaState([string]$UserId) {
    try {
        (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements" -ErrorAction Stop).perUserMfaState
    }
    catch { 'Error' }
}

# --- Regisztrációs riport --------------------------------------------------
Write-Host "MFA regisztrációs riport lekérdezése..." -ForegroundColor Cyan
$regLookup = @{}
try {
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object { $regLookup[$_.Id] = $_ }
}
catch {
    Write-Warning "Regisztrációs riport nem elérhető (P1/P2 licenc kell): $($_.Exception.Message). Folytatás -Detailed módban."
    $Detailed = $true
}

# Registration report (methodsRegistered) értékek -> olvasható név
function ConvertFrom-RegMethod([string]$m) {
    switch -Wildcard ($m) {
        'mobilePhone'                        { 'SMS/Hívás (mobil)' }
        'alternateMobilePhone'               { 'SMS/Hívás (alternatív mobil)' }
        'officePhone'                        { 'Irodai telefon (hívás)' }
        'microsoftAuthenticatorPush'         { 'Authenticator (push)' }
        'microsoftAuthenticatorPasswordless' { 'Authenticator (passwordless)' }
        'softwareOneTimePasscode'            { 'OATH TOTP (szoftveres)' }
        'hardwareOneTimePasscode'            { 'OATH TOTP (hardveres)' }
        'fido2SecurityKey'                   { 'FIDO2 kulcs' }
        'passKey*'                           { 'Passkey' }
        'windowsHelloForBusiness'            { 'Windows Hello for Business' }
        'temporaryAccessPass'                { 'Temporary Access Pass' }
        'email'                              { 'E-mail (csak SSPR)' }
        default                              { $m }
    }
}

# --- Feldolgozás -----------------------------------------------------------
$results = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($u in $users) {
    $i++
    Write-Progress -Activity 'Userek feldolgozása' -Status "$i / $($users.Count)  $($u.UserPrincipalName)" `
        -PercentComplete (($i / $users.Count) * 100)

    $reg = $regLookup[$u.Id]

    # --- Kikényszerítés ---
    $perUser = if ($SkipPerUserState) { 'n/a' } else { Get-PerUserMfaState $u.Id }
    $caHit   = @($caEnforced   | Where-Object { Test-UserInPolicy $u.Id $_ } | ForEach-Object { $_.DisplayName })
    $caRO    = @($caReportOnly | Where-Object { Test-UserInPolicy $u.Id $_ } | ForEach-Object { $_.DisplayName })

    $reasons = @()
    if ($perUser -in 'enforced', 'enabled') { $reasons += "Per-user MFA ($perUser)" }
    if ($securityDefaults)                  { $reasons += 'Security Defaults' }
    if ($caHit.Count -gt 0)                 { $reasons += 'Conditional Access' }

    # --- Módszerek összegyűjtése egységes nevekkel ---
    $friendly = [System.Collections.Generic.List[string]]::new()
    $phones   = [System.Collections.Generic.List[string]]::new()
    $emails   = [System.Collections.Generic.List[string]]::new()
    $devices  = [System.Collections.Generic.List[string]]::new()

    if ($Detailed) {
        try {
            foreach ($m in (Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop)) {
                $type = $m.AdditionalProperties['@odata.type']
                switch -Wildcard ($type) {
                    '*microsoftAuthenticatorAuthenticationMethod' {
                        $friendly.Add('Authenticator (push)')
                        $devices.Add("$($m.AdditionalProperties['displayName']) [$($m.AdditionalProperties['deviceTag'])]")
                    }
                    '*phoneAuthenticationMethod' {
                        $pt = $m.AdditionalProperties['phoneType']
                        $label = switch ($pt) {
                            'mobile'          { 'SMS/Hívás (mobil)' }
                            'alternateMobile' { 'SMS/Hívás (alternatív mobil)' }
                            'office'          { 'Irodai telefon (hívás)' }
                            default           { "Telefon ($pt)" }
                        }
                        $friendly.Add($label)
                        $phones.Add("${pt}: $($m.AdditionalProperties['phoneNumber']) (SMS sign-in: $($m.AdditionalProperties['smsSignInState']))")
                    }
                    '*emailAuthenticationMethod' {
                        $friendly.Add('E-mail (csak SSPR)')
                        $emails.Add($m.AdditionalProperties['emailAddress'])
                    }
                    '*fido2AuthenticationMethod' {
                        $friendly.Add('FIDO2 kulcs')
                        $devices.Add("FIDO2: $($m.AdditionalProperties['displayName'])")
                    }
                    '*windowsHelloForBusinessAuthenticationMethod' { $friendly.Add('Windows Hello for Business') }
                    '*softwareOathAuthenticationMethod'            { $friendly.Add('OATH TOTP (szoftveres)') }
                    '*hardwareOathAuthenticationMethod'            { $friendly.Add('OATH TOTP (hardveres)') }
                    '*temporaryAccessPassAuthenticationMethod'     { $friendly.Add('Temporary Access Pass') }
                    '*platformCredentialAuthenticationMethod'      { $friendly.Add('Platform Credential (macOS)') }
                }
            }
        }
        catch { $friendly.Add("HIBA: $($_.Exception.Message)") }
    }
    elseif ($reg.MethodsRegistered) {
        foreach ($m in $reg.MethodsRegistered) { $friendly.Add((ConvertFrom-RegMethod $m)) }
    }

    $methods = @($friendly | Select-Object -Unique)
    $has = { param($pattern) [bool]($methods | Where-Object { $_ -like $pattern }) }

    $hasFido = & $has 'FIDO2*'
    $hasPk   = & $has 'Passkey*'
    $hasWhfb = & $has 'Windows Hello*'
    $hasAuth = & $has 'Authenticator*'
    $hasOath = & $has 'OATH*'
    $hasSms  = & $has '*SMS/Hívás*'
    $hasOff  = & $has 'Irodai*'
    $hasTap  = & $has 'Temporary*'

    $strength =
        if     ($hasFido -or $hasPk -or $hasWhfb) { 'Phishing-resistant (FIDO2/Passkey/WHfB)' }
        elseif ($hasAuth -or $hasOath)            { 'App alapú (Authenticator/OATH)' }
        elseif ($hasSms -or $hasOff)              { 'Csak SMS/hívás (gyenge)' }
        else                                      { 'Nincs MFA módszer' }

    # Ha nincs regisztrációs riport (P1 nélkül), az MFA-regisztráció a módszerekből számolódik
    $mfaRegistered = if ($reg) { $reg.IsMfaRegistered } else { $strength -ne 'Nincs MFA módszer' }

    $row = [ordered]@{
        DisplayName            = $u.DisplayName
        UserPrincipalName      = $u.UserPrincipalName
        Mail                   = $u.Mail
        UserType               = $u.UserType
        AccountEnabled         = $u.AccountEnabled
        MfaEnforcedEffective   = ($reasons.Count -gt 0)
        EnforcedBy             = $reasons -join '; '
        PerUserMfaState        = $perUser
        SecurityDefaults       = $securityDefaults
        CA_Policies_Enforced   = $caHit -join '; '
        CA_Policies_ReportOnly = $caRO -join '; '
        MfaRegistered          = $mfaRegistered
        MfaStrength            = $strength
        MfaMethods             = $methods -join '; '
        DefaultMfaMethod       = if ($reg.DefaultMfaMethod) { ConvertFrom-RegMethod $reg.DefaultMfaMethod } else { '' }
        Has_Authenticator      = $hasAuth
        Has_SMS_Call           = $hasSms
        Has_OfficePhone        = $hasOff
        Has_Email              = & $has 'E-mail*'
        Has_FIDO2_Passkey      = ($hasFido -or $hasPk)
        Has_WindowsHello       = $hasWhfb
        Has_OATH               = $hasOath
        Has_TAP                = $hasTap
        MfaCapable             = $reg.IsMfaCapable
        PasswordlessCapable    = $reg.IsPasswordlessCapable
        SsprRegistered         = $reg.IsSsprRegistered
        IsAdmin                = $reg.IsAdmin
        Detail_Phones          = $phones -join '; '
        Detail_Emails          = $emails -join '; '
        Detail_Devices         = $devices -join '; '
    }
    $results.Add([pscustomobject]$row)
}
Write-Progress -Activity 'Userek feldolgozása' -Completed

# --- Kimenet ---------------------------------------------------------------
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "`nRiport mentve: $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green

$total    = $results.Count
$enforced = @($results | Where-Object MfaEnforcedEffective).Count
Write-Host "Összes user:              $total"
Write-Host "MFA kikényszerítve:       $enforced"
Write-Host "MFA NINCS kikényszerítve: $($total - $enforced)" -ForegroundColor Yellow

$results | Select-Object UserPrincipalName, MfaEnforcedEffective, MfaStrength, MfaMethods, DefaultMfaMethod |
    Sort-Object MfaStrength | Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
