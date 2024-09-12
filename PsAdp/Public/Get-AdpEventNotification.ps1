function Get-AdpEventNotification {
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $Uri='https://api.adp.com/core/v1/event-notification-messages'
    Write-Debug "GET $Uri"

    $Headers = @{
        prefer = '/adp/long-polling'
        Authorization = "Bearer {0}" -f $AccessToken
    }
    Write-Debug ($Headers | ConvertTo-Json)

    $Response = Invoke-WebRequest -Uri $Uri -Method Get -Certificate $Certificate -Headers $Headers

    if ( $null -ne $Response ) {

        $Content = $Response.Content | ConvertFrom-Json
        
        $Events = $Content.events

        # get the message-id from the header and add it to the body
        $Events | Add-Member -Name 'adp-msg-msgid' -Type NoteProperty -Value $Response.Headers.'adp-msg-msgid'[0]

        $Events
    }

}