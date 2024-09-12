BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Get-AdpEventNotification' {

  Context "Parameter validation" {

      BeforeAll {
          $Command = Get-Command 'Get-AdpEventNotification'
      } 

      $Parameters = @(
        @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
        @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
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
          $AccessToken = (New-Guid).Guid
          $Certifcate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()

          Mock Invoke-WebRequest

          # act
          Get-AdpEventNotification -Certificate $Certifcate -AccessToken $AccessToken -Debug
      }

      It 'uses the correct Uri' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Uri -eq 'https://api.adp.com/core/v1/event-notification-messages'
          }
      }

      It 'uses the correct Method' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Method -eq 'Get'
          }
      }

      It 'uses prefer header' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Headers.prefer -eq '/adp/long-polling'
          }
      }

      It 'uses a Certificate' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Certificate -eq $Certifcate
          }
      }

  }
  
  Context 'Response' {

    BeforeEach {
      # arrange
      $AccessToken = (New-Guid).Guid
      $Certifcate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()

      Mock Invoke-WebRequest {
        $Content = '{
          "events": [
            {
              "creationDateTime": "2020-09-21T00:00:00Z",
              "effectiveDateTime": "2020-10-01T00:00:00Z",
              "eventID": "8d7195fa-107e-4cb2-a8be-ce62cfa84164",
              "eventNameCode": {
                  "codeValue": "worker.hire"
              }
            }
          ]
        }'
        $Response = New-MockObject -Type  Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject
        $Response | Add-Member -Type NoteProperty -Name 'Content' -Value $Content -Force
        $Response | Add-Member -Type NoteProperty -Name 'Headers' -Value @{'adp-msg-msgid'=,'0123456789'} -Force
        $Response
      }

      # act
      $Events = Get-AdpEventNotification -Certificate $Certifcate -AccessToken $AccessToken -Debug
    }

    It 'add the adp-msg-msgid to the body' {
      $Events.'adp-msg-msgid' | Should -Not -Be $null
    }

  }

}