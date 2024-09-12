function Remove-AdpEventNotification {

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [Alias('adp-msg-msgid')]
        [string]$MessageId
    )

    $BaseUri='https://api.adp.com/core/v1/event-notification-messages'
    $Uri = "$BaseUri/{0}" -f $MessageId
    Write-Debug "DELETE $Uri"

    $Headers = @{
        Accept = 'application/json'
        Authorization = "Bearer {0}" -f $AccessToken
    }

    if ($PSCmdlet.ShouldProcess($MessageId, "DELETE /event-notification-messages")) {

        $Response = Invoke-WebRequest -Uri $Uri -Method Delete -Certificate $Certificate -Headers $Headers

        if ($null -ne $Response) {
            $Content = $Response.Content | ConvertFrom-Json
            $Content.events
        }

    }

}