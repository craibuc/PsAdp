function Set-AdpWorkerStringField {

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [Object]$Certificate,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$AssociateOid,

        [Parameter(Mandatory)]
        [string]$ItemID,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Value
    )
    
    begin {

        $Headers = @{
            Accept = 'application/json'
            Authorization = "Bearer $AccessToken"
        }
        
    }
    
    process {

        $Body = @{
            "events" = @(
                @{
                    "data" = @{
                        "eventContext" = @{
                            "worker" = @{
                                "associateOID" = $AssociateOID
                                "person" = @{
                                    "customFieldGroup" = @{
                                        "stringField" = @{
                                            "itemID" = $ItemID
                                        }
                                    }
                                }
                            }
                        }
                        "transform" = @{
                            "worker" = @{
                                "person" = @{
                                    "customFieldGroup" = @{
                                        "stringField" = @{
                                            "nameCode" = @{
                                                "nameCode" = $Name
                                            }
                                            "stringValue" = $Value
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )
        } | ConvertTo-Json -Depth 10
        Write-Debug $Body

        $Uri = 'https://api.adp.com/events/hr/v1/worker.person.custom-field.string.change'
        Write-Debug "Uri: $Uri"
    
        if ($PSCmdlet.ShouldProcess($AssociateOid, "Set-AdpWorkerStringField")) {
            $Response = Invoke-WebRequest -Uri $Uri -Method Post -Certificate $Certificate -Headers $Headers -Body $Body -ContentType 'application/json'
    
            $Content = if ( $null -ne $Response ) {$Response.Content | ConvertFrom-Json}
            $Content
        }

    }

    end {}
}