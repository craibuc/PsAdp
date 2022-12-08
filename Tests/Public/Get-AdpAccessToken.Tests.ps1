BeforeAll {

    $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

    $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
    . (Join-Path $PublicPath $SUT)

}

Describe 'Get-AdpAccessToken' {

    Context "Parameter validation" {

        BeforeAll {
            $Command = Get-Command 'Get-AdpAccessToken'
        } 

        $Parameters = @(
            @{ParameterName='ClientId'; Type='[string]'; Mandatory=$true}
            @{ParameterName='ClientSecret'; Type='[string]'; Mandatory=$true}
            @{ParameterName='CertificatePath'; Type='[string]'; Mandatory=$true}
        )

        Context 'Data type' {
        
            It "<ParameterName> is a <Type>" -TestCases $Parameters {
                param ($ParameterName, $Type)
                $Command | Should -HaveParameter $ParameterName -Type $Type
            }

        }

        Context "Mandatory" {
            it "<ParameterName> Mandatory is <Mandatory>" -TestCases $Parameters {
                param($ParameterName, $Mandatory)
                
                if ($Mandatory) { $Command | Should -HaveParameter $ParameterName -Mandatory }
                else { $Command | Should -HaveParameter $ParameterName -Not -Mandatory }
            }    
        }
    
    } # /Context

    Context 'Request' {

        BeforeEach {
            # arrange
            Mock Invoke-WebRequest {
                @{
                    Content = @{access_token=(New-Guid).Guid; token_type='Bearer'; expires_in=3600; scope='api'} | ConvertTo-Json
                }
            }

            $ExpectedCertifcate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()

            Mock Get-PfxCertificate {
                $ExpectedCertifcate
            }

            $Expected = @{
                ClientId = (New-Guid).Guid
                ClientSecret = (New-Guid).Guid
                CertificatePath = '/path/to/certificate.pfx'
            }
         
            # act
            Get-AdpAccessToken @Expected
        }

        It 'uses the correct Uri' {
            Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                $Uri -eq 'https://accounts.adp.com/auth/oauth/v2/token'
            }
        }

        It 'uses the correct Method' {
            Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                $Method -eq 'Post'
            }
        }

        It 'uses the correct ContentType header' {
            Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                $ContentType -eq 'application/x-www-form-urlencoded'
            }
        }

        It 'uses the correct Body' {
            Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                $Body.client_id -eq $Expected.ClientId -and
                $Body.client_secret -eq $Expected.ClientSecret -and
                $Body.grant_type -eq 'client_credentials'
            }
        }

        It 'loads a Certificate' {
            Assert-MockCalled -CommandName Get-PfxCertificate -ParameterFilter {
                $FilePath -eq $Expected.CertificatePath
            }
        }

        It 'uses a Certificate' {
            Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                $Certificate -eq $ExpectedCertifcate
            }
        }

    }
    
    Context 'Response' {
        BeforeEach {

            Mock Get-PfxCertificate {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
            }

            $Expected = @{
                ClientId = (New-Guid).Guid
                ClientSecret = (New-Guid).Guid
                CertificatePath = '/path/to/certificate.pfx'
            }
        }
        
        Context 'When valid credentials are supplied' {
                BeforeEach {
                    $ExpectedAccessToken = @{access_token=(New-Guid).Guid; token_type='Bearer'; expires_in=3600; scope='api'}

                    Mock Invoke-WebRequest {
                        @{
                            Content = $ExpectedAccessToken | ConvertTo-Json
                        }
                    }

                    $Token = Get-AdpAccessToken @Expected
                }
                It 'returns an AccessToken' {
                    $Token.access_token | Should -Be ([pscustomobject]$ExpectedAccessToken).access_token
                }
            }

        Context 'When invalid credentials is supplied' {
            BeforeEach {
                Mock Get-PfxCertificate {
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
                }
    
                Mock Invoke-WebRequest {
                    $UnauthorizedResponse = New-Object System.Net.Http.HttpResponseMessage 401
                    $Phrase = 'Response status code does not indicate success: 401 ().'
        
                    $Exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new($Phrase,$UnauthorizedResponse)

                    $ErrorId = "PsAdp.Get-AdpAccessToken - [$( $UnauthorizedResponse.StatusCode )]"
                    $ErrorRecord = [Management.Automation.ErrorRecord]::new($Exception, $ErrorId, [System.Management.Automation.ErrorCategory]::AuthenticationError, $null)

                    $Message = '{
                        "error": "invalid_client",
                        "error_description": "The given client credentials were not valid"
                    }'
                    $ErrorDetails = [System.Management.Automation.ErrorDetails]::new($Message)
                    $ErrorRecord.ErrorDetails = $ErrorDetails

                    Write-Error $ErrorRecord
                }    
            }

            It 'throws an invalid-credentials excaption' {
                { Get-AdpAccessToken @Expected -ErrorAction Stop -Debug } | Should -Throw 'The given client credentials were not valid'
            }
        }

        Context 'When an invalid certificate is supplied' {
            BeforeEach {
                Mock Get-PfxCertificate {
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
                }
    
                Mock Invoke-WebRequest {
                    $UnauthorizedResponse = New-Object System.Net.Http.HttpResponseMessage 401
                    $Phrase = 'Response status code does not indicate success: 401 ().'
        
                    $Exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new($Phrase,$UnauthorizedResponse)

                    $ErrorId = "PsAdp.Get-AdpAccessToken - [$( $UnauthorizedResponse.StatusCode )]"
                    $ErrorRecord = [Management.Automation.ErrorRecord]::new($Exception, $ErrorId, [System.Management.Automation.ErrorCategory]::AuthenticationError, $null)

                    $Message = '{
                        "error": "invalid_certificate",
                        "error_description": "proper client ssl certificate was not presented"
                    }'
                    $ErrorDetails = [System.Management.Automation.ErrorDetails]::new($Message)
                    $ErrorRecord.ErrorDetails = $ErrorDetails

                    Write-Error $ErrorRecord
                }    
            }

            It 'throws an invalid-certificate excaption' {
                { Get-AdpAccessToken @Expected -ErrorAction Stop } | Should -Throw 'proper client ssl certificate was not presented' 
            }
        }

    }
}