BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Get-AdpWorker' {

  BeforeAll {
      $BaseUri = 'https://api.adp.com/hr/v2/workers'

      $AccessToken = (New-Guid).Guid
      $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()

      $AssociateOID='0123456789'
  }

  Context "Parameter validation" {

    BeforeAll {
        $Command = Get-Command 'Get-AdpWorker'
    } 

    $Parameters = @(
      @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
      @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
      @{ParameterName='AssociateId'; Type='[string]'; Mandatory=$true}
      @{ParameterName='Select'; Type='[string[]]'; Mandatory=$false}
      @{ParameterName='filter'; Type='[string[]]'; Mandatory=$false}
      @{ParameterName='Masked'; Type='[switch]'; Mandatory=$false}
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
          Mock Invoke-WebRequest {
              $Content = '{
                  "workers": [
                      {
                          "associateOID": "0123456789"
                      }
                  ]
              }'
              $Response = New-MockObject -Type  Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject
              $Response | Add-Member -Type NoteProperty -Name 'Content' -Value $Content -Force
              $Response
          }
      }

      Context 'When the AssociateID parameter is supplied' {

          It 'uses the correct URI' {
              # 
              Get-AdpWorker -AccessToken $AccessToken -Certificate $Certificate -AssociateId $AssociateOID
              # 
              Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                  $Uri -like "$BaseUri/$AssociateOID*"
              }
          }

          Context 'When the Select parameter is supplied' {

              It 'uses the correct URI' {
                  # arrange
                  $Select = 'associateOID','workers/person/legalName','workers/person/customFieldGroup/stringFields','workerStatus','worker/person/governmentIDs'
                  # act
                  Get-AdpWorker -AccessToken $AccessToken -Certificate $Certificate -AssociateId $AssociateOID -Select $Select
                  # assert
                  Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                      $Uri -eq "$BaseUri/$AssociateOID`?`$select=$( $Select -join ',' )"
                  }
              }
  
          }
  
      }

      Context 'When the AssociateID parameter is NOT supplied' {

          BeforeEach {
  
              Mock Invoke-WebRequest {
                  Write-Debug "***** Page 1 *****"
                  $Response = New-MockObject -Type  Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject
                  $Response | Add-Member -Type NoteProperty -Name 'StatusCode' -Value 204 -Force
                  $Response
              }

              Mock Invoke-WebRequest {
                  Write-Debug "***** Page 0 *****"
                  $Content = '{
                      "workers": [
                          {
                              "associateOID": "0123456789"
                          }
                      ]
                  }'
                  $Response = New-MockObject -Type  Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject
                  $Response | Add-Member -Type NoteProperty -Name 'Content' -Value $Content -Force
                  $Response | Add-Member -Type NoteProperty -Name 'StatusCode' -Value 200 -Force
                  $Response
              } -ParameterFilter { $Uri -like 'https://api.adp.com/hr/v2/workers?top=100&skip=0*' }
  
          }

          it "makes multiple requests to get all pages" {
              # 
              Get-AdpWorker -AccessToken $AccessToken -Certificate $Certificate
              # 
              Assert-MockCalled Invoke-WebRequest -Times 2 -Exactly
          }

      }

      Context 'When the Masked parameter is supplied' {

          It 'uses the correct header' {
              # 
              Get-AdpWorker -AccessToken $AccessToken -Certificate $Certificate -AssociateId $AssociateOID -Masked
              # 
              Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
                  $Headers.Accept -eq "application/json;masked=true"
              }
          }

      }

  }

}