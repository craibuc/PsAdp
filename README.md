# PsAdt
A PowerShell wrapper of the ADP API.

## Configuration

Add environment variables to `$profile`:

```powershell
$Env:ADT_API_CLIENT_ID = 'guid'
$Env:ADT_API_CLIENT_SECRET = 'guid'
```

## Usage

### Get-AdpAccessToken

```powershell
Get-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -CertificatePath '/path/to/certificate.pfx'
```