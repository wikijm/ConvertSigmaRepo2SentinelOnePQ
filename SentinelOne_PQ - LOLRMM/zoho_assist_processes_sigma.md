```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "zaservice.exe" or src.process.image.path contains "ZMAgent.exe" or src.process.image.path contains "ZA_Access.exe" or src.process.image.path contains "ZohoMeeting.exe" or src.process.image.path contains "Zohours.exe" or src.process.image.path contains "zohotray.exe" or src.process.image.path contains "ZohoURSService.exe" or src.process.image.path contains "ZA_Access.exe" or src.process.image.path contains "Zaservice.exe" or src.process.image.path contains "za_connect.exe" or src.process.image.path contains "connect.exe") or (tgt.process.image.path contains "zaservice.exe" or tgt.process.image.path contains "ZMAgent.exe" or tgt.process.image.path contains "ZA_Access.exe" or tgt.process.image.path contains "ZohoMeeting.exe" or tgt.process.image.path contains "Zohours.exe" or tgt.process.image.path contains "zohotray.exe" or tgt.process.image.path contains "ZohoURSService.exe" or tgt.process.image.path contains "ZA_Access.exe" or tgt.process.image.path contains "Zaservice.exe" or tgt.process.image.path contains "za_connect.exe" or tgt.process.image.path contains "connect.exe")))
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
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - zaservice.exe
            - ZMAgent.exe
            - ZA_Access.exe
            - ZohoMeeting.exe
            - Zohours.exe
            - zohotray.exe
            - ZohoURSService.exe
            - ZA_Access.exe
            - Zaservice.exe
            - za_connect.exe
            - connect.exe
    selection_image:
        Image|endswith:
            - zaservice.exe
            - ZMAgent.exe
            - ZA_Access.exe
            - ZohoMeeting.exe
            - Zohours.exe
            - zohotray.exe
            - ZohoURSService.exe
            - ZA_Access.exe
            - Zaservice.exe
            - za_connect.exe
            - connect.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Zoho Assist
level: medium
```
