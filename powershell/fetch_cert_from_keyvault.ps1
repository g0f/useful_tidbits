#Run this as a scheduled task nightly
#This assumes oyu already have a netsh http ssl binding active
#use azure arc and managed identity. your managed identity needs secret user and certificate user roles in the key vault.
$keyVaultName = "mykeyvault"
$certificateName = "certificate name (in key vault)"

$logFile = "C:\logs\ssrs_cert_$(Get-Date -Format 'yyyy-MM-dd').log"
if (!(Test-Path (Split-Path $logFile))) { New-Item -ItemType Directory -Path (Split-Path $logFile) -Force }

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $logFile -Append | Write-Host
}

Write-Log "Starting certificate check"

try {
    $currentBinding = netsh http show sslcert ipport=0.0.0.0:443 | Out-String
    if ($currentBinding -match "Certificate Hash\s+:\s+([A-F0-9]+)") {
        $currentThumbprint = $matches[1]
        Write-Log "Current thumbprint: $currentThumbprint"
    } else {
        $currentThumbprint = $null
        Write-Log "No current SSL binding found"
    }

    Write-Log "Connecting to Azure..."
    Connect-AzAccount -Identity | Out-Null
    
    Write-Log "Getting certificate from Key Vault..."
    $kvCert = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName
    $kvThumbprint = $kvCert.Thumbprint
    Write-Log "Key Vault thumbprint: $kvThumbprint"

    if ($currentThumbprint -eq $kvThumbprint) {
        Write-Log "Thumbprints match - no update needed"
        exit 0
    }

    Write-Log "Thumbprints differ - updating certificate..."

    $certSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $certificateName -AsPlainText
    $certBytes = [System.Convert]::FromBase64String($certSecret)
    $pfxPath = "C:\Temp\cert.pfx"
    [System.IO.File]::WriteAllBytes($pfxPath, $certBytes)

    $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My
    $newThumbprint = $cert.Thumbprint
    Write-Log "Imported certificate with thumbprint: $newThumbprint"

    Write-Log "Updating SSL binding with new certificate..."
    netsh http update sslcert ipport=0.0.0.0:443 certhash=$newThumbprint | Out-Null
    
    Remove-Item $pfxPath -Force
    Write-Log "Certificate updated successfully"

} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
