function Get-AdpWorkerPhoto {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$AssociateOid,

        [Parameter(Mandatory)]
        [string]$OutFile
    )

    $Headers = @{
        Authorization = "Bearer $AccessToken"
    }

    $Uri = "https://api.adp.com/hr/v2/workers/$AssociateOid/worker-images/photo"
    Write-Debug "Uri: $Uri"

    $Response = Invoke-WebRequest -Uri $Uri -Method Get -Certificate $Certificate -Headers $Headers -OutFile $OutFile

    if ( $null -ne $Response -and $Response.StatusCode -eq 200) {
        $Response.Content
    }

}