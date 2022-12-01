<#
.SYNOPSIS
Retrieve an access token from ADP's API.

.PARAMETER ClientId

.PARAMETER ClientSecret

.PARAMETER CertificatePath
Path to the certificate (pfx)

.EXAMPLE
Get-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -CertificatePath '/path/to/certificate.pfx'

#>
function Get-AdpAccessToken
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$ClientSecret,

        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    $Uri='https://accounts.adp.com/auth/oauth/v2/token'
    $Body = @{     
        client_id = $ClientId
        client_secret = $ClientSecret
        grant_type = 'client_credentials'
    }

    $Certificate = Get-PfxCertificate -FilePath $CertificatePath

    $Response = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -Certificate $Certificate -ContentType 'application/x-www-form-urlencoded'
    $Response.Content | ConvertFrom-Json
    
}
