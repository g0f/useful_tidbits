# Simplified Nightly Application Proxy Certificate Update Script
# Uses Azure Automation Variable to track last deployed certificate thumbprint

#the managed identity running this needs secrets user and certificates user roleon the keyvault as well as Application.ReadWrite.All, Application.ReadWrite.OwnedBy, OnPremisesPublishingProfiles.ReadWrite.All
#you also have to go through steps 2.1 and 2.2 in here to have the required sections: https://learn.microsoft.com/en-us/graph/application-proxy-configure-api?tabs=http

#$ManagedIdentityObjectId = "your-managed-identity-object-id"
#Connect-MgGraph -Scopes "Application.ReadWrite.All"
#$Graph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
#@("Application.ReadWrite.All", "OnPremisesPublishingProfiles.ReadWrite.All") | ForEach-Object {
#    $Permission = $Graph.AppRoles | Where-Object {$_.Value -eq $_}
#    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -PrincipalId $ManagedIdentityObjectId -ResourceId $Graph.Id -AppRoleId $Permission.Id
#}

param(
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = "yourkvname",
    
    [Parameter(Mandatory = $false)]
    [string]$CertToUploadName = "yourcertname",
    
    [Parameter(Mandatory = $false)]
    [string]$AppObjectId = "app proxy object id",
    
    [Parameter(Mandatory = $false)]
    [string]$AutomationVariableName = "variable in azure automation for storing previous cert",
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceUpdate = $false
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [CERT-UPDATE] [$Level] $Message"
}

Write-Log "Starting nightly certificate update check"

try {
    Write-Log "Connecting to Azure with Managed Identity"
    Connect-AzAccount -Identity | Out-Null
    
    Write-Log "Retrieving certificate from Key Vault: $KeyVaultName/$CertToUploadName"
    $certSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertToUploadName -ErrorAction Stop
    
    $certSecretValue = $certSecret.SecretValue | ConvertFrom-SecureString -AsPlainText
    $pfxBytes = [Convert]::FromBase64String($certSecretValue)
    
    $newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $pfxBytes,
        "",
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    )
    
    $newThumbprint = $newCert.Thumbprint
    Write-Log "Key Vault certificate thumbprint: $newThumbprint"
    
    $lastThumbprint = $null
    try {
        $lastThumbprint = Get-AutomationVariable -Name $AutomationVariableName -ErrorAction SilentlyContinue
        if ($lastThumbprint) {
            Write-Log "Last deployed thumbprint: $lastThumbprint"
        } else {
            Write-Log "No previous thumbprint found in automation variable"
        }
    }
    catch {
        Write-Log "Could not read automation variable: $($_.Exception.Message)" "WARN"
    }
    
    if (-not $ForceUpdate -and $lastThumbprint -eq $newThumbprint) {
        Write-Log "Certificate thumbprint unchanged - no update needed"
        Write-Log "Nightly check completed - no action required"
        return
    }
    
    if ($ForceUpdate) {
        Write-Log "Force update requested - proceeding with certificate update"
    } else {
        Write-Log "Certificate thumbprint changed - update needed"
    }
    
    Write-Log "Acquiring Microsoft Graph access token"
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
    if (-not $token) {
        throw "Failed to acquire Microsoft Graph access token"
    }
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    Write-Log "Verifying Application Proxy configuration"
    $appUri = "https://graph.microsoft.com/beta/applications/$AppObjectId"
    $selectUri = "$appUri" + '?$select=displayName,onPremisesPublishing'
    
    $currentApp = Invoke-RestMethod -Uri $selectUri -Headers $headers -Method GET
    
    if (-not $currentApp.onPremisesPublishing -or -not $currentApp.onPremisesPublishing.isOnPremPublishingEnabled) {
        throw "Application Proxy is not enabled for this application"
    }
    
    Write-Log "Application Proxy enabled for: $($currentApp.displayName)"
    Write-Log "External URL: $($currentApp.onPremisesPublishing.externalUrl)"
    
    Write-Log "Updating Application Proxy certificate using PFX without password"
    
    Write-Log "Certificate details:"
    Write-Log "  - PFX bytes size: $($pfxBytes.Length) bytes"
    Write-Log "  - Certificate subject: $($newCert.Subject)"
    Write-Log "  - Certificate expires: $($newCert.NotAfter)"
    
    Write-Log "Connecting to Microsoft Graph using REST API approach..."
    Write-Log "Updating Application Proxy certificate using direct REST API..."
    Write-Log "NOTE: Using optimized method for Key Vault imported certificates"
    
    # Key vault certs doesnt have a password, but one is needed for the import. Create a random string...
    try {
        Write-Log "Recreating PFX with random password for Key Vault compatibility..."
        
        $randomPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
        Write-Log "Generated random password for PFX recreation (32 characters)"
        
        $newPfxBytes = $newCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $randomPassword)
        
        Write-Log "PFX recreated - Original size: $($pfxBytes.Length) bytes, New size: $($newPfxBytes.Length) bytes"
        
        $updatePayload = @{
            onPremisesPublishing = @{
                verifiedCustomDomainKeyCredential = @{
                    type = "X509CertAndPassword"
                    value = [Convert]::ToBase64String($newPfxBytes)
                }
                verifiedCustomDomainPasswordCredential = @{ 
                    value = $randomPassword
                }
            }
        } | ConvertTo-Json -Depth 10
        
        $updateUri = "https://graph.microsoft.com/beta/applications/$AppObjectId"
        $response = Invoke-RestMethod -Uri $updateUri -Headers $headers -Method PATCH -Body $updatePayload -ContentType "application/json"
        
        Write-Log "Certificate update API call completed successfully"
        
        $randomPassword = $null
        
        Start-Sleep -Seconds 10
        

        $verifyApp = Invoke-RestMethod -Uri $selectUri -Headers $headers -Method GET
        
        if ($verifyApp.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata.thumbprint -eq $newThumbprint) {
            Write-Log "SUCCESS: Certificate verified - thumbprint matches!"
            Write-Log "Certificate subject: $($verifyApp.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata.subjectName)"
            Write-Log "Certificate expires: $($verifyApp.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata.expiryDate)"
        }
        else {
            Write-Log "WARNING: Certificate update may have failed - thumbprint mismatch" "WARN"
            Write-Log "Expected: $newThumbprint" "WARN"
            Write-Log "Actual: $($verifyApp.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata.thumbprint)" "WARN"
            
            if ($verifyApp.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata) {
                Write-Log "Certificate metadata found - this may be a timing issue" "WARN"
            } else {
                throw "Certificate update failed - no certificate metadata found after update"
            }
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Log "Certificate update failed: $errorMessage" "ERROR"
        
        if ($_.Exception.Response) {
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorDetails = $reader.ReadToEnd()
                Write-Log "Detailed error response: $errorDetails" "ERROR"
            }
            catch {
                Write-Log "Could not read detailed error response" "WARN"
            }
        }
        
        if ($errorMessage -like "*403*" -or $errorMessage -like "*401*" -or $errorMessage -like "*Forbidden*" -or $errorMessage -like "*Unauthorized*") {
            Write-Log "Permission issue detected - check managed identity permissions" "ERROR"
            Write-Log "Required permissions: Application.ReadWrite.All" "ERROR"
        }
        
        throw "Certificate update failed: $errorMessage"
    }
    
    Write-Log "Certificate updated successfully using direct REST API"
    
    try {
        Set-AutomationVariable -Name $AutomationVariableName -Value $newThumbprint
        Write-Log "Updated automation variable '$AutomationVariableName' with new thumbprint"
    }
    catch {
        Write-Log "Failed to update automation variable: $($_.Exception.Message)" "WARN"
        Write-Log "Manual intervention may be required to prevent unnecessary updates" "WARN"
    }
    
    Start-Sleep -Seconds 3
    try {
        $verifyApp = Invoke-RestMethod -Uri $selectUri -Headers $headers -Method GET
        if ($verifyApp.onPremisesPublishing.verifiedCustomDomainKeyCredential) {
            Write-Log "Verification: Certificate found in Application Proxy configuration"
        }
    }
    catch {
        Write-Log "Verification failed, but update reported success: $($_.Exception.Message)" "WARN"
    }
    
    Write-Log "Certificate update completed successfully"
    Write-Log "New thumbprint: $newThumbprint"
    Write-Log "Certificate expires: $($newCert.NotAfter)"
    
}
catch {
    Write-Log "Certificate update failed: $($_.Exception.Message)" "ERROR"
    
    if ($_.Exception.InnerException) {
        Write-Log "Inner exception: $($_.Exception.InnerException.Message)" "ERROR"
    }
    
    Write-Log "Nightly certificate check completed with errors" "ERROR"
    exit 1
}

Write-Log "Nightly certificate update completed successfully"
