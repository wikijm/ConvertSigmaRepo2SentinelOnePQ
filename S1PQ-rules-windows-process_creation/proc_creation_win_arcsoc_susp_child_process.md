```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\ArcSOC.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe")) and (not (tgt.process.image.path contains "\\cmd.exe" and tgt.process.cmdline="cmd.exe /c \"ver\""))))
```


# Original Sigma Rule:
```yaml
title: Suspicious ArcSOC.exe Child Process
id: 8e95e73e-ba02-4a87-b4d7-0929b8053038
status: experimental
description: |
    Detects script interpreters, command-line tools, and similar suspicious child processes of ArcSOC.exe.
    ArcSOC.exe is the process name which hosts ArcGIS Server REST services. If an attacker compromises an ArcGIS
    Server system and uploads a malicious Server Object Extension (SOE), they can send crafted requests to the corresponding
    service endpoint and remotely execute code from the ArcSOC.exe process.
references:
    - https://reliaquest.com/blog/threat-spotlight-inside-flax-typhoons-arcgis-compromise/
    - https://enterprise.arcgis.com/en/server/12.0/administer/windows/inside-an-arcgis-server-site.htm
author: Micah Babinski
date: 2025-11-25
tags:
    - attack.execution
    - attack.t1059
    - attack.t1203
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\ArcSOC.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    filter_main_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine: 'cmd.exe /c "ver"'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
