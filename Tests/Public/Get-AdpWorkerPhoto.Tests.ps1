BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Get-AdpWorkerPhoto' {

  Context "Parameter validation" {

      BeforeAll {
          $Command = Get-Command 'Get-AdpWorkerPhoto'
      } 

      $Parameters = @(
        @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
        @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
        @{ParameterName='AssociateOID'; Type='[string]'; Mandatory=$true}
        @{ParameterName='OutFile'; Type='[string]'; Mandatory=$true}
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
          $ExpectedPath = '/path/to/file.jpeg'

          Mock Invoke-WebRequest

          # act
          Get-AdpWorkerPhoto -Certificate $Certifcate -AccessToken $AccessToken -AssociateOID $AssociateOID -OutFile $ExpectedPath
      }

      It 'uses the correct Uri' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Uri -eq "https://api.adp.com/hr/v2/workers/$AssociateOid/worker-images/photo"
          }
      }

      It 'uses the correct Method' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Method -eq 'Get'
          }
      }

      It 'uses a Certificate' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Certificate -eq $Certifcate
          }
      }

      It 'sets the OutFile' {
        Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
            $OutFile -eq $ExpectedPath
        }
    }

  }
  
}