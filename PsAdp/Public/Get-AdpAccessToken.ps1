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

    Write-Debug "ClientId: $ClientId"
    Write-Debug "ClientSecret: $ClientSecret"
    Write-Debug "CertificatePath: $CertificatePath"

    $Uri='https://accounts.adp.com/auth/oauth/v2/token'
    $Body = @{     
        client_id = $ClientId
        client_secret = $ClientSecret
        grant_type = 'client_credentials'
    }

    try {
        $Certificate = Get-PfxCertificate -FilePath $CertificatePath

        $Response = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -Certificate $Certificate -ContentType 'application/x-www-form-urlencoded'

        if ( $null -ne $Response ) {
            $Content = $Response.Content | ConvertFrom-Json

            $ExpiresAt = (Get-Date).AddSeconds( $Content.expires_in )
            $Content |  Add-Member -Name 'expires_at' -Type NoteProperty -Value $ExpiresAt

            $Content
        }
    }
    catch [System.IO.FileNotFoundException] {

        $FileNotFoundException = [System.IO.FileNotFoundException]::new('The certificate file was not found.',$CertificatePath)
        $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) - $($_.Exception.Message)"
        $ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $ErrorRecord = [Management.Automation.ErrorRecord]::new($FileNotFoundException, $ErrorId, $ErrorCategory, $CertificatePath)

        Write-Error -ErrorRecord $ErrorRecord
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {

        $ErrorDetails = $_.ErrorDetails.Message | ConvertFrom-Json

        if ( $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized ) {

            $InvalidCredentialException = [System.Security.Authentication.InvalidCredentialException]::new($ErrorDetails.error_description)
            $ErrorCategory = [System.Management.Automation.ErrorCategory]::AuthenticationError
            $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) [$( $_.Exception.Response.StatusCode )]"
            $ErrorRecord = [Management.Automation.ErrorRecord]::new($InvalidCredentialException, $ErrorId, $ErrorCategory, $null)

        }
        else {

            $ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified
            $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) - $( $_.Exception.Message )"
            $ErrorRecord = [Management.Automation.ErrorRecord]::new($_.Exception, $ErrorId, $ErrorCategory, $null)
        }

        Write-Error -ErrorRecord $ErrorRecord

    }
    catch {

        $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) - $($_.Exception.Message)"
        $ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified
        $ErrorRecord = [Management.Automation.ErrorRecord]::new($_.Exception, $ErrorId, $ErrorCategory, $null)
        
        Write-Error -ErrorRecord $ErrorRecord
    }
    
}
