```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\WindowsTerminal.exe" or src.process.image.path contains "\\wt.exe") and ((tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\csc.exe") or (tgt.process.image.path contains "C:\\Users\\Public\\" or tgt.process.image.path contains "\\Downloads\\" or tgt.process.image.path contains "\\Desktop\\" or tgt.process.image.path contains "\\AppData\\Local\\Temp\\" or tgt.process.image.path contains "\\Windows\\TEMP\\") or (tgt.process.cmdline contains " iex " or tgt.process.cmdline contains " icm" or tgt.process.cmdline contains "Invoke-" or tgt.process.cmdline contains "Import-Module " or tgt.process.cmdline contains "ipmo " or tgt.process.cmdline contains "DownloadString(" or tgt.process.cmdline contains " /c " or tgt.process.cmdline contains " /k " or tgt.process.cmdline contains " /r "))) and (not ((tgt.process.cmdline contains "Import-Module" and tgt.process.cmdline contains "Microsoft.VisualStudio.DevShell.dll" and tgt.process.cmdline contains "Enter-VsDevShell") or (tgt.process.cmdline contains "\\AppData\\Local\\Packages\\Microsoft.WindowsTerminal_" and tgt.process.cmdline contains "\\LocalState\\settings.json") or (tgt.process.cmdline contains "C:\\Program Files\\Microsoft Visual Studio\\" and tgt.process.cmdline contains "\\Common7\\Tools\\VsDevCmd.bat")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious WindowsTerminal Child Processes
id: 8de89e52-f6e1-4b5b-afd1-41ecfa300d48
status: test
description: Detects suspicious children spawned via the Windows Terminal application which could be a sign of persistence via WindowsTerminal (see references section)
references:
    - https://persistence-info.github.io/Data/windowsterminalprofile.html
    - https://twitter.com/nas_bench/status/1550836225652686848
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-25
modified: 2023-02-14
tags:
    - attack.execution
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WindowsTerminal.exe'
            - '\wt.exe'
    selection_susp:
        - Image|endswith:
              # Add more LOLBINS
              - '\rundll32.exe'
              - '\regsvr32.exe'
              - '\certutil.exe'
              - '\cscript.exe'
              - '\wscript.exe'
              - '\csc.exe'
        - Image|contains:
              # Add more suspicious paths
              - 'C:\Users\Public\'
              - '\Downloads\'
              - '\Desktop\'
              - '\AppData\Local\Temp\'
              - '\Windows\TEMP\'
        - CommandLine|contains:
              # Add more suspicious commandline
              - ' iex '
              - ' icm'
              - 'Invoke-'
              - 'Import-Module '
              - 'ipmo '
              - 'DownloadString('
              - ' /c '
              - ' /k '
              - ' /r '
    filter_builtin_visual_studio_shell:
        CommandLine|contains|all:
            - 'Import-Module'
            - 'Microsoft.VisualStudio.DevShell.dll'
            - 'Enter-VsDevShell'
    filter_open_settings:
        CommandLine|contains|all:
            - '\AppData\Local\Packages\Microsoft.WindowsTerminal_'
            - '\LocalState\settings.json'
    filter_vsdevcmd:
        CommandLine|contains|all:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - '\Common7\Tools\VsDevCmd.bat'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Other legitimate "Windows Terminal" profiles
level: medium
```
