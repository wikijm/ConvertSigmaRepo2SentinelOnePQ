```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\reg.exe" and tgt.process.cmdline contains "query" and (tgt.process.cmdline contains "-v" or tgt.process.cmdline contains "/v" or tgt.process.cmdline contains "–v" or tgt.process.cmdline contains "—v" or tgt.process.cmdline contains "―v")) or ((tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe") and (tgt.process.cmdline contains "Get-ItemPropertyValue" or tgt.process.cmdline contains "gpv"))) and (tgt.process.cmdline contains "\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" or tgt.process.cmdline contains "\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" or tgt.process.cmdline contains "\SOFTWARE\Microsoft\Windows NT\CurrentVersion" or tgt.process.cmdline contains "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" or tgt.process.cmdline contains "\SOFTWARE\Microsoft\Windows Defender" or tgt.process.cmdline contains "\SYSTEM\CurrentControlSet\Services" or tgt.process.cmdline contains "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks")))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery via Registry Queries
id: 0022869c-49f7-4ff2-ba03-85ac42ddac58
status: experimental
description: Detects attempts to query system information directly from the Windows Registry.
references:
    - https://cert.gov.ua/article/6277849
    - https://github.com/redcanaryco/atomic-red-team/blob/75fa21076dcefa348a7521403cdd6bfc4e88623c/atomics/T1082/T1082.md
    - https://github.com/redcanaryco/atomic-red-team/blob/75fa21076dcefa348a7521403cdd6bfc4e88623c/atomics/T1124/T1124.md
author: lazarg
date: 2025-06-12
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains: 'query'
        CommandLine|contains|windash: '-v'
    selection_cmd_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Get-ItemPropertyValue'
            - 'gpv'
    selection_keys:
        CommandLine|contains:
            - '\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' # Contains time zone details
            - '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' # Holds network configuration details
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion' # Provides details about the OS
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' # Lists installed programs
            - '\SOFTWARE\Microsoft\Windows Defender' # Details about defender state
            - '\SYSTEM\CurrentControlSet\Services' # Details about existing services
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' # Details about existing scheduled tasks
    condition: 1 of selection_cmd_* and selection_keys
falsepositives:
    - Unlikely
level: low
```
