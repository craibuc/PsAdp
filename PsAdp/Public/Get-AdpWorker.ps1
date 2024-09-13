<#
.SYNOPSIS
Retrieve a worker or workers from ADP's API.

.PARAMETER AccessToken

.PARAMETER Certificate
An instance of the certificate (pfx) file.

.PARAMETER Select
Array of paths that represent data nodes.

.PARAMETER Filter
Array of paths that represent data nodes.

.PARAMETER Masked
Mask the SSN if present.

.EXAMPLE
$Certificate = Get-PfxCertificate -FilePath $CertificatePath
$AccessToken = New-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -Certificate $Certificate

Get-AdpWorker -AccessToken $AccessToken.access_token -Certificate $Certificate

.EXAMPLE
$Certificate = Get-PfxCertificate -FilePath $CertificatePath
$AccessToken = New-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -Certificate $Certificate

Get-AdpWorker -AccessToken $AccessToken.access_token -Certificate $Certificate -Select 'workers/person/legalName','workers/person/governmentIDs'

Only include legal name and government ID in the data.

.EXAMPLE
$Certificate = Get-PfxCertificate -FilePath $CertificatePath
$AccessToken = New-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -Certificate $Certificate

Get-AdpWorker -AccessToken $AccessToken.access_token -Certificate $Certificate -Select 'associateOID','workers/person/legalName','workers/person/customFieldGroup/stringFields','workerStatus','worker/person/governmentIDs'

More data elements.

.EXAMPLE
$Certificate = Get-PfxCertificate -FilePath $CertificatePath
$AccessToken = New-AdpAccessToken -ClientId $Env:ADT_API_CLIENT_ID -ClientSecret $env:ADT_API_CLIENT_SECRET -Certificate $Certificate

Get-AdpWorker -AccessToken $AccessToken.access_token -Certificate $Certificate -Filter "workers/workAssignments/assignmentStatus/statusCode/codeValue eq 'T'"

Get (T)erminated workers.
#>
function Get-AdpWorker
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Certificate,

        [Parameter(Mandatory)]
        [Alias('access_token')]
        [string]$AccessToken,

        [Parameter(ParameterSetName='One',Mandatory)]
        [string]$AssociateId,

        [Parameter(ParameterSetName='One')]
        [Parameter(ParameterSetName='All')]
        [string[]]$Select,

        [Parameter(ParameterSetName='All')]
        [string[]]$Filter,

        [Parameter()]
        [switch]$Masked
    )

    Write-Debug "AccessToken: $AccessToken"
    Write-Debug "AssociateId: $AssociateId"
    Write-Debug "Select: $Select"
    Write-Debug "Filter: $Filter"
    Write-Debug "Masked: $Masked"

    $BaseUri = $AssociateId ? "https://api.adp.com/hr/v2/workers/$AssociateId" : 'https://api.adp.com/hr/v2/workers'
    Write-Debug "BaseUri: $BaseUri"

    $Headers = @{
        Accept = "application/json;masked=$Masked".ToLower()
        Authorization = "Bearer $AccessToken"
    }
    Write-Debug ($Headers | ConvertTo-Json)

    $Page = 0
    $PageSize = 100

    #
    # collect querystring variables
    #

    $Query = @{}

    # applies to One and All
    if ( $null -ne $Select) { $Query.'$select' = ($Select -join ',') }
    
    # applies to All
    if ($PSCmdlet.ParameterSetName -eq 'All') { $Query.top = $PageSize }
    if ($PSCmdlet.ParameterSetName -eq 'All' -and $null -ne $Filter) { $Query.'$filter' = ($Filter -join ',') }

    try {

        do {

            if ($PSCmdlet.ParameterSetName -eq 'All') { $Query.skip = ($Page * $PageSize) }

            $QS=@()
            $QS += foreach($Q in $Query.GetEnumerator()) {
                "{0}={1}" -f $Q.Name, $Q.Value
            }

            $Uri = $QS.Length -gt 0 ? ( "{0}?{1}" -f $BaseUri, ($QS -join '&') ) : $BaseUri
            Write-Debug "Uri: $Uri"

            $Response = Invoke-WebRequest -Uri $Uri -Method Get -Certificate $Certificate -Headers $Headers
            Write-Debug "StatusCode: $( $Response.StatusCode )"

            if ( $null -ne $Response -and $Response.StatusCode -eq 200) {
                $Content = $Response.Content | ConvertFrom-Json
                Write-Output $Content.workers
            }

            $Page += 1

        } while ( $Response.StatusCode -eq 200 -and -not $AssociateId)

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
