 $hd = Split-Path $MyInvocation.MyCommand.Path

 $testDir = (Resolve-Path "$hd/../test").Path 

 $folders = Get-ChildItem $testDir
 foreach($folder in $folders)
 {

    $testFolder = $folder.FullName
    
    cd $testFolder
    dotnet test
 }
 


 cd "$hd/../"