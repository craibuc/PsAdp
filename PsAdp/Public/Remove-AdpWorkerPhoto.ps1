function Remove-AdpWorkerPhoto {

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$AssociateOID
    )

    $Headers = @{
        Accept = 'application/json'
        Authorization = "Bearer $AccessToken"
    }

    $Body = @{
        "events" = @(
            @{
                "data" = @{
                    "eventContext" = @{
                        "worker" = @{
                            "associateOID" = $AssociateOID
                        }
                    }
                }
                "eventNameCode" = @{
                    "codeValue" = "worker.photo.remove"
                }
            }
        )
    } | ConvertTo-Json -Depth 5
    Write-Debug $Body

    $Uri = 'https://api.adp.com/events/hr/v1/worker.photo.remove'
    Write-Debug "Uri: $Uri"

    if ($PSCmdlet.ShouldProcess($MessageId, "DELETE /event-notification-messages")) {
        $Response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers -Body $Body -ContentType 'application/json' -Certificate $Certificate

        if ( $null -ne $Response ) {
            $Response.Content | ConvertFrom-Json
        }
    }

}