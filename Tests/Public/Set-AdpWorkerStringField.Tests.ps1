BeforeAll {

  $ProjectDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
  $PublicPath = Join-Path $ProjectDirectory "/PsAdp/Public/"

  $SUT = (Split-Path -Leaf $PSCommandPath) -replace '\.Tests\.', '.'
  . (Join-Path $PublicPath $SUT)

}

Describe 'Set-AdpWorkerStringField' {

  Context "Parameter validation" {

      BeforeAll {
          $Command = Get-Command 'Set-AdpWorkerStringField'
      } 

      $Parameters = @(
        @{ParameterName='Certificate'; Type='[object]'; Mandatory=$true}
        @{ParameterName='AccessToken'; Type='[string]'; Mandatory=$true}
        @{ParameterName='AssociateOID'; Type='[string]'; Mandatory=$true}
        @{ParameterName='ItemID'; Type='[string]'; Mandatory=$true}
        @{ParameterName='Name'; Type='[string]'; Mandatory=$true}
        @{ParameterName='Value'; Type='[string]'; Mandatory=$true}
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
          $ItemID = '111111'
          $Name = 'Lorem'
          $Value = 'Ipsum'

          Mock Invoke-WebRequest

          # act
          Set-AdpWorkerStringField -Certificate $Certifcate -AccessToken $AccessToken -AssociateOID $AssociateOID -ItemID $ItemID -Name $Name -Value $Value
      }

      It 'uses the correct Uri' {
          Assert-MockCalled -CommandName Invoke-WebRequest -ParameterFilter {
              $Uri -eq 'https://api.adp.com/events/hr/v1/worker.person.custom-field.string.change'
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
            $Data.events[0].data.eventContext.worker.person.customFieldGroup.stringField.itemID -eq $ItemID -and
            $Data.events[0].data.transform.worker.person.customFieldGroup.stringField.nameCode.nameCode -eq $Name -and
            $Data.events[0].data.transform.worker.person.customFieldGroup.stringField.stringValue -eq $Value
        }

    }

  }
  
}