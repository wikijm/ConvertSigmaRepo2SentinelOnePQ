```sql
// Translated content (automatically translated on 28-11-2025 01:37:18):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "screenconnect.clientservice.exe" or src.process.image.path contains "connectwisecontrol.client.exe" or src.process.image.path contains "screenconnect.windowsclient.exe" or src.process.image.path contains "connectwisechat-customer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ConnectWise Control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - screenconnect.clientservice.exe
    - connectwisecontrol.client.exe
    - screenconnect.windowsclient.exe
    - connectwisechat-customer.exe
  condition: selection
id: 4a407e58-10a2-4e23-8fad-2787ba64a5fb
status: experimental
description: Detects potential processes activity of ConnectWise Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ConnectWise Control
level: medium
```
