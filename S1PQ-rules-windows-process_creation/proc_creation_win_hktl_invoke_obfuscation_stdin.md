```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline matches "cmd.{0,5}(?:/c|/r).+powershell.+(?:\\$\\{?input\\}?|noexit).+\\"")
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation STDIN+ Launcher
id: 6c96fc76-0eb1-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of stdin to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 25)
author: Jonathan Cheong, oscd.community
date: 2020-10-15
modified: 2024-04-15
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Example 1: c:\windows\sYstEm32\CmD.eXE /C"echO\Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -NoEXiT -"
        # Example 2: c:\WiNDOws\sysTEm32\cmd.EXe /C " ECHo Invoke-Expression (New-Object Net.WebClient).DownloadString | POwersHELl -nol ${EXEcUtIONCONTeXT}.INvOkEComMANd.InvOKEScRIPt( $InpUt )"
        CommandLine|re: 'cmd.{0,5}(?:/c|/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
