```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\toolsiq.exe" or src.process.image.path contains "\\zaservice.exe" or src.process.image.path contains "\\ZMAgent.exe" or src.process.image.path contains "\\ZohoMeeting.exe" or src.process.image.path contains "\\Zohours.exe" or src.process.image.path contains "\\zohotray.exe" or src.process.image.path contains "\\ZohoURSService.exe" or src.process.image.path contains "\\ZA_Access.exe" or src.process.image.path contains "\\za_connect.exe" or src.process.image.path contains "\\connect.exe") or (tgt.process.image.path contains "\\toolsiq.exe" or tgt.process.image.path contains "\\zaservice.exe" or tgt.process.image.path contains "\\ZMAgent.exe" or tgt.process.image.path contains "\\ZohoMeeting.exe" or tgt.process.image.path contains "\\Zohours.exe" or tgt.process.image.path contains "\\zohotray.exe" or tgt.process.image.path contains "\\ZohoURSService.exe" or tgt.process.image.path contains "\\ZA_Access.exe" or tgt.process.image.path contains "\\za_connect.exe" or tgt.process.image.path contains "\\connect.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Zoho Assist RMM Tool Process Activity
id: f57c281c-5d94-43d1-8ba2-d2c95d01e871
status: experimental
description: |
    Detects potential processes activity of Zoho Assist RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
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
            - '\\toolsiq.exe'
            - '\\zaservice.exe'
            - '\\ZMAgent.exe'
            - '\\ZohoMeeting.exe'
            - '\\Zohours.exe'
            - '\\zohotray.exe'
            - '\\ZohoURSService.exe'
            - '\\ZA_Access.exe'
            - '\\za_connect.exe'
            - '\\connect.exe'
    selection_image:
        Image|endswith:
            - '\\toolsiq.exe'
            - '\\zaservice.exe'
            - '\\ZMAgent.exe'
            - '\\ZohoMeeting.exe'
            - '\\Zohours.exe'
            - '\\zohotray.exe'
            - '\\ZohoURSService.exe'
            - '\\ZA_Access.exe'
            - '\\za_connect.exe'
            - '\\connect.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Zoho Assist
level: medium
```
