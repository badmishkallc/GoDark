
Write-Host "${env:APPVEYOR_BUILD_FOLDER}"
$items = gci "${env:APPVEYOR_BUILD_FOLDER}\*" -Include *.nupkg -Recurse
foreach($item in $items) {
    if($item.FullName.Contains("Tests")) {
        continue;     
    } 
    $pkg = $item.FullName
    $server = "https://www.myget.org/F/badmishka-coreclr/api/v2/package";
    nuget push $pkg -ApiKey ($env:api_key)  -Source $server  
}