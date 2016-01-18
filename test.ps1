 $hd = Split-Path $MyInvocation.MyCommand.Path
 
 cd $hd/test/BadMishka.GoDark.Tests
 dnx test
 cd $hd