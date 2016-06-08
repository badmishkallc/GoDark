# Home Directory
$hd = Split-Path $MyInvocation.MyCommand.Path

# Install the latest dotnet cli   
if (Get-Command "dotnet.exe" -ErrorAction SilentlyContinue) {
    Write-Host "dotnet SDK already installed"
	dotnet --version 
    return
} 

Write-Host "Installing dotnet SDK"
$installDotNetSdkPs1 = Join-Path $hd "install-dotnet-sdk.ps1"

if((Test-Path $installDotNetSdkPs1)) {
    Remove-Item $installDotNetSdkPs1 -Force
}

Write-Debug $installDotNetSdkPs1
Invoke-WebRequest "https://raw.githubusercontent.com/dotnet/cli/rel/1.0.0/scripts/dev-dotnet.ps1" -OutFile $installDotNetSdkPs1
& $installDotNetSdkPs1