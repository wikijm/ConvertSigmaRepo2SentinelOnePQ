```sql
// Translated content (automatically translated on 16-09-2025 00:45:56):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\ProgramData\\JWrapper-Remote Access\\JWAppsSharedConfig\\restricted\\" or tgt.process.image.path contains "\\ProgramData\\JWrapper-Remote Access\\JWAppsSharedConfig\\") and (tgt.process.image.path contains "\\SimpleService.exe" or tgt.process.image.path contains "\\serviceconfig.xml")))
```


# Original Sigma Rule:
```yaml
title: Malicious Remote Access Execution Via Simple Help RMM Software
id: bfc9f08f-59c2-4346-807e-a67b6d7621fd
status: stable
description: This rule can detects additional remote access tools, often masquerading as legitimate software, to maintain persistence and access to compromised systems. In one observed incident, adversaries installed the Simple Help Remote Monitoring and Management (RMM) tool after gaining initial access through ScreenConnect.
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Phyo Paing Htun
date: 2024/10/16
tags:
    - attack.persistence
    - attack.t1543.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - '\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\restricted\'
            - '\ProgramData\JWrapper-Remote Access\JWAppsSharedConfig\'
        Image|endswith:
            - '\SimpleService.exe'
            - '\serviceconfig.xml'
    condition: selection
falsepositives:
    - Unknown
level: high```
