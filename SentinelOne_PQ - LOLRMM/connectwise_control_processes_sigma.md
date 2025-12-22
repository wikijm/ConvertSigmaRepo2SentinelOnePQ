```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "connectwisechat-customer.exe" or src.process.image.path contains "connectwisecontrol.client.exe" or src.process.image.path contains "screenconnect.windowsclient.exe") or (tgt.process.image.path contains "connectwisechat-customer.exe" or tgt.process.image.path contains "connectwisecontrol.client.exe" or tgt.process.image.path contains "screenconnect.windowsclient.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ConnectWise Control RMM Tool Process Activity
id: 2208c309-8a9b-49d0-b96f-cff473d97748
status: experimental
description: |
    Detects potential processes activity of ConnectWise Control RMM tool
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
            - connectwisechat-customer.exe
            - connectwisecontrol.client.exe
            - screenconnect.windowsclient.exe
    selection_image:
        Image|endswith:
            - connectwisechat-customer.exe
            - connectwisecontrol.client.exe
            - screenconnect.windowsclient.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ConnectWise Control
level: medium
```
