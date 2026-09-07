```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\Freshservice.DiscoveryProbe.ScanService.exe" or src.process.image.path contains "\\Freshservice.DiscoveryProbe.Window.exe" or src.process.image.path contains "\\plink.exe" or src.process.image.path contains "\\FSAgentService.exe" or src.process.image.path contains "\\FSAgentAutoUpdate.exe" or src.process.image.path contains "\\FSWmiScanner.exe") or (tgt.process.image.path contains "\\Freshservice.DiscoveryProbe.ScanService.exe" or tgt.process.image.path contains "\\Freshservice.DiscoveryProbe.Window.exe" or tgt.process.image.path contains "\\plink.exe" or tgt.process.image.path contains "\\FSAgentService.exe" or tgt.process.image.path contains "\\FSAgentAutoUpdate.exe" or tgt.process.image.path contains "\\FSWmiScanner.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Freshservice RMM Tool Process Activity
id: 4992eedc-3a1c-52df-9de8-ed06cef332c9
status: experimental
description: |
    Detects potential processes activity of Freshservice RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\Freshservice.DiscoveryProbe.ScanService.exe'
            - '\\Freshservice.DiscoveryProbe.Window.exe'
            - '\\plink.exe'
            - '\\FSAgentService.exe'
            - '\\FSAgentAutoUpdate.exe'
            - '\\FSWmiScanner.exe'
    selection_image:
        Image|endswith:
            - '\\Freshservice.DiscoveryProbe.ScanService.exe'
            - '\\Freshservice.DiscoveryProbe.Window.exe'
            - '\\plink.exe'
            - '\\FSAgentService.exe'
            - '\\FSAgentAutoUpdate.exe'
            - '\\FSWmiScanner.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Freshservice
level: medium
```
