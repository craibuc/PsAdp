<#
.SYNOPSIS
Retrieve an access token from ADP's API.

.PARAMETER ClientId

.PARAMETER ClientSecret

.PARAMETER Certificate
The certificate (pfx) file

.EXAMPLE
$Certificate = Get-PfxCertificate -FilePath $CertificatePath
Get-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -Certificate $Certificate

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
        [object]$Certificate
    )

    Write-Debug "ClientId: $ClientId"
    Write-Debug "ClientSecret: $ClientSecret"

    $Uri='https://accounts.adp.com/auth/oauth/v2/token'
    $Body = @{     
        client_id = $ClientId
        client_secret = $ClientSecret
        grant_type = 'client_credentials'
    }

    try {

        $Response = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -Certificate $Certificate -ContentType 'application/x-www-form-urlencoded'

        if ( $null -ne $Response ) {
            $Content = $Response.Content | ConvertFrom-Json

            $ExpiresAt = (Get-Date).AddSeconds( $Content.expires_in )
            $Content |  Add-Member -Name 'expires_at' -Type NoteProperty -Value $ExpiresAt

            $Content
        }
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
