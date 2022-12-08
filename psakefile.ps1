Properties {
  $RepositoryName=$Env:REPOSITORY_NAME
  $ModuleName='PsAdp'
}

Task Symlink -description "Create a symlink for '$ModuleName' module" {
  $Here = Get-Location
  $ModulePath = ($ENV:PSModulePath -split ([System.Environment]::OSVersion -eq '' ? ';' : ':'))[0]
  Push-Location $ModulePath #~/.local/share/powershell/Modules
  ln -s "$Here/$ModuleName" $ModuleName
  Pop-Location
}

Task Publish -description "Publish module '$ModuleName' to repository '$($RepositoryName)'" {
  Publish-Module -name $ModuleName -Repository $RepositoryName -NuGetApiKey $NuGetApiKey
}
