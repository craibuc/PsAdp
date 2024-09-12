BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Remove-AdpWorkerPhoto' {

  Context "Parameter validation" {

      BeforeAll {
          $Command = Get-Command 'Remove-AdpWorkerPhoto'
      } 

      $Parameters = @(
        @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
        @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
        @{ParameterName='AssociateOID'; Type='[string]'; Mandatory=$true}
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

          $AssociateOID = (New-Guid).Guid

          Mock Invoke-WebRequest

          # act
          Remove-AdpWorkerPhoto -Certificate $Certifcate -AccessToken $AccessToken -AssociateOID $AssociateOID
      }

      It 'uses the correct Uri' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Uri -eq 'https://api.adp.com/events/hr/v1/worker.photo.remove'
          }
      }

      It 'uses the correct Method' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Method -eq 'Post'
          }
      }

      It 'uses the correct ContentType' {
        Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
            $ContentType -eq 'application/json'
        }
    }

      It 'uses a Certificate' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Certificate -eq $Certifcate
          }
      }

      It 'uses the correct body' {
        Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
            $Data = $Body | ConvertFrom-Json
            $Data.events[0].data.eventContext.worker.associateOID -eq $AssociateOID -and
            $Data.events[0].eventNameCode.codeValue -eq 'worker.photo.remove'
        }

    }

  }
  
}