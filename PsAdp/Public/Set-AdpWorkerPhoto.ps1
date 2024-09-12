function Set-AdpWorkerPhoto {

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$AssociateOID,

        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Debug "AssociateOID: $AssociateOID"

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
            }
        )
    } | ConvertTo-Json -Depth 5

    $Form = @{
        json = $Body
        datafile = Get-Item -Path $Path
    }

    $Uri = 'https://api.adp.com/events/hr/v1/worker.photo.upload'
    Write-Debug "Uri: $Uri"

    if ($PSCmdlet.ShouldProcess("$AssociateOID / $Path", "Set-AdpWorkerPhoto")) {

        try {

            $Response = Invoke-WebRequest -Uri $Uri -Method Post -Certificate $Certificate -Headers $Headers -Form $Form

            if ( $null -ne $Response ) {
                $Response.Content | ConvertFrom-Json
            }
                
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {

            $ErrorDetails = $_.ErrorDetails.Message | ConvertFrom-Json

            if ( $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized ) {
                throw 'Unauthorized [401]'
            #     $InvalidCredentialException = [System.Security.Authentication.InvalidCredentialException]::new($ErrorDetails.error_description)
            #     $ErrorCategory = [System.Management.Automation.ErrorCategory]::AuthenticationError
            #     $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) [$( $_.Exception.Response.StatusCode )]"
            #     $ErrorRecord = [Management.Automation.ErrorRecord]::new($InvalidCredentialException, $ErrorId, $ErrorCategory, $null)
            }
            elseif ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Forbidden) {
                throw 'Forbidden [403]'
            }
            elseif ( $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::BadRequest ) {
                throw ('Bad request [400]: {0}' -f $ErrorDetails.confirmMessage.resourceMessages[0].processMessages[0].userMessage.messageTxt)
            #     $ErrorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation
            #     $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) [$( $_.Exception.Response.StatusCode )]"
            #     $ErrorRecord = [Management.Automation.ErrorRecord]::new($_.Exception, $ErrorId, $ErrorCategory, $null)
            }
            else {
            #     $ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified
            #     $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) - $( $_.Exception.Message )"
            #     $ErrorRecord = [Management.Automation.ErrorRecord]::new($_.Exception, $ErrorId, $ErrorCategory, $null)
            }
    
            # Write-Error -ErrorRecord $ErrorRecord
    
        }
        catch {

            $ErrorId = "$($MyInvocation.MyCommand.Module.Name).$($MyInvocation.MyCommand.Name) - $($_.Exception.Message)"
            $ErrorCategory = [System.Management.Automation.ErrorCategory]::NotSpecified
            $ErrorRecord = [Management.Automation.ErrorRecord]::new($_.Exception, $ErrorId, $ErrorCategory, $null)
            
            Write-Error -ErrorRecord $ErrorRecord
        }
    
    }

}