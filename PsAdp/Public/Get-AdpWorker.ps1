<#
.SYNOPSIS
Retrieve an access token from ADP's API.

.PARAMETER AccessToken

.PARAMETER CertificatePath
Path to the certificate (pfx)

.PARAMETER Select

.PARAMETER Filter

.EXAMPLE
Get-AdpWorker -AccessToken $Env:ADT_API_CLIENT_ID -CertificatePath '/path/to/certificate.pfx'

.EXAMPLE
Get-AdpWorker -Select 'workers/person/legalName','workers/person/governmentIDs' -AccessToken $Env:ADT_API_CLIENT_ID -CertificatePath '/path/to/certificate.pfx'

Only include legal name and government ID in the data.

.EXAMPLE
Get-AdpWorker -Filter "workers/workAssignments/assignmentStatus/statusCode/codeValue eq 'T'" -AccessToken $Env:ADT_API_CLIENT_ID -CertificatePath '/path/to/certificate.pfx'

Get (T)erminated workers.
#>
function Get-AdpWorker
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias('access_token')]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$CertificatePath,

        [Parameter()]
        [string]$AssociateId,

        [Parameter()]
        [string[]]$Select,

        [Parameter()]
        [string[]]$Filter

    )

    Write-Debug "AccessToken: $AccessToken"
    Write-Debug "CertificatePath: $CertificatePath"
    Write-Debug "AssociateId: $AssociateId"
    Write-Debug "Select: $Select"
    Write-Debug "Filter: $Filter"

    $BaseUri='https://accounts.adp.com/hr/v2/workers'
    
    $Headers = @{
        Accept = 'application/json;masked=false'
        Authorization = "Bearer $AccessToken"
    }

    try {

        $Certificate = Get-PfxCertificate -FilePath $CertificatePath

        $Page = 0
        $PageSize = 100
        
        do {

            # $Uri = "$BaseUri`?`$top={0}&`$skip={1}" -f $PageSize, ($Page * $PageSize)

            $Uri = 
                if ( $AssociateId ) { "$BaseUri/{0}" -f $AssociateId }
                else { "$BaseUri`?`$top={0}&`$skip={1}" -f $PageSize, ($Page * $PageSize) }
            
            # add select restriction
            if ( $null -ne $Select) {
                $Uri = "$Uri&`$select={0}" -f ($Select -join ',')
            }

            # add filter restriction
            if ( $null -ne $Filter) {
                $Uri = "$Uri&`$filter={0}" -f ($Filter -join ',')
            }
            
            Write-Debug "Uri: $Uri"

            $Response = Invoke-WebRequest -Uri $Uri -Method Get -Certificate $Certificate -Headers $Headers

            $Content = if ( $null -ne $Response ) {$Response.Content | ConvertFrom-Json}

            Write-Output $Content.workers
    
            $Page += 1

        } while ( $Response.StatusCode -eq 200 -and -not $AssociateId)

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
