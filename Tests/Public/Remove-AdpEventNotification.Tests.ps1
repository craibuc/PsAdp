BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Remove-AdpEventNotification' {

  Context "Parameter validation" {

      BeforeAll {
          $Command = Get-Command 'Remove-AdpEventNotification'
      } 

      $Parameters = @(
        @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
        @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
        @{ParameterName='MessageId'; Type='[string]'; Mandatory=$true}
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

          $MessageId = (New-Guid).Guid

          Mock Invoke-WebRequest

          # act
          Remove-AdpEventNotification -Certificate $Certifcate -AccessToken $AccessToken -MessageId $MessageId
      }

      It 'uses the correct Uri' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Uri -eq "https://api.adp.com/core/v1/event-notification-messages/$MessageId"
          }
      }

      It 'uses the correct Method' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Method -eq 'Delete'
          }
      }

      It 'uses a Certificate' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Certificate -eq $Certifcate
          }
      }

  }
  
}