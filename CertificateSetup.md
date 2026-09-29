# Certificate Setup

Entra pins the public key and does no chain validation so we can use self-signed certificates.

## Linux / macOS (openssl)

```bash
# Generate key and public cert files
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout lr-app.key -out lr-app.cer \
  -subj "/CN=mde-live-response"

# Save as PKCS#12 for the script (prompts for a password, set one)
openssl pkcs12 -export -out lr-app.pfx \
  -inkey lr-app.key -in lr-app.cer -name "mde-live-response" \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256

# Key material no longer needed on disk unencrypted
shred -u lr-app.key
chmod 600 lr-app.pfx

# SHA-1 thumbprint, compare to what Entra shows after upload
openssl x509 -in lr-app.cer -noout -fingerprint -sha1
```

Note: Using `-keypbe`/`-certpbe` keeps the bundle readable by modern .NET. If loading fails on older runtimes, re-export with `-legacy`.

## Windows (PowerShell)

```powershell
# Generate key pair in the user store
$cert = New-SelfSignedCertificate `
    -Subject 'CN=mde-live-response' `
    -CertStoreLocation Cert:\CurrentUser\My `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable -KeySpec Signature `
    -NotAfter (Get-Date).AddYears(1)

# Save public cert for Entra
Export-Certificate -Cert $cert -FilePath .\lr-app.cer -Type CERT

# Save PKCS#12 bundle for the script
$pfxPwd = Read-Host 'PFX password' -AsSecureString
Export-PfxCertificate `
    -Cert $cert `
    -FilePath .\lr-app.pfx `
    -Password $pfxPwd `
    -CryptoAlgorithmOption AES256_SHA256

# Print SHA-1 thumbprint to confirm against Entra
$cert.Thumbprint

# Lock down the bundle
icacls .\lr-app.pfx /inheritance:r /grant:r "$($env:USERNAME):(R)"

# Optional: drop the store copy once the .pfx is backed up
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
```

Keep the last step if you want the file to be the single copy of the credential. Skip it if you would rather load from the store, which takes a small edit to the script's `Certificate` parameter
set since it currently accepts a file path only.

`-CryptoAlgorithmOption AES256_SHA256` avoids the legacy TripleDES default. Remove that parameter if you're running from Windows Server 2012 R2 and earlier.

# Attaching the certificate

Only the public cert gets uploaded to Entra. The `.pfx` and `.key` stay on your machine.  Treat these like passwords.

## Entra Portal

App registration > Certificates & secrets > Certificates > Upload certificate, then select
`lr-app.cer`.

## Azure CLI

```powershell
# Create a base64/PEM version of the certificate
[Convert]::ToBase64String($cert.RawData) | Set-Content .\lr-app-b64.cer -Encoding ascii

az ad app credential reset --id "$APP_ID" --cert "@lr-app-b64.cer" --append

az ad app credential list --id "$APP_ID" --cert -o table
```

## Microsoft Graph PowerShell

`-KeyCredentials` replaces the whole collection, so read the existing entries and pass them back alongside the new one. Loading through `X509Certificate2` makes this format-agnostic, since
`RawData` is DER whether the file on disk was PEM or DER.

```powershell
$appObjectId = '<ObjectId from the app registration step>'

$pub = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Resolve-Path ./lr-app.cer).Path)

$new = @{
    Type        = 'AsymmetricX509Cert'
    Usage       = 'Verify'
    Key         = $pub.RawData
    DisplayName = 'CN=mde-live-response'
}

$existing = (Get-MgApplication -ApplicationId $appObjectId).KeyCredentials
Update-MgApplication -ApplicationId $appObjectId -KeyCredentials @($existing + $new)

(Get-MgApplication -ApplicationId $appObjectId).KeyCredentials |
    Select-Object DisplayName, StartDateTime, EndDateTime, @{n='Thumbprint';e={
        [BitConverter]::ToString($_.CustomKeyIdentifier).Replace('-','') }}
```

Notes:

- Change the script to store the `.pfx` in SecretManagement or a KMS.
- Rotate before expiry: generate a new pair, attach the new `.cer`, cut over, then delete the old credential in Entra. Two certs can be registered at once, so there is no outage window.
- The app's `Machine.LiveResponse` grant is tenant-wide. Treat this credential as equivalent to SYSTEM on every onboarded device in scope.
