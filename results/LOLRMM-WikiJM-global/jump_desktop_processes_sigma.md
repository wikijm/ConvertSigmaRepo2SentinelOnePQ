```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "jumpclient.exe" or src.process.image.path contains "jumpdesktop.exe" or src.process.image.path contains "jumpservice.exe" or src.process.image.path contains "jumpconnect.exe" or src.process.image.path contains "jumpupdater.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Jump Desktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - jumpclient.exe
    - jumpdesktop.exe
    - jumpservice.exe
    - jumpconnect.exe
    - jumpupdater.exe
  condition: selection
id: 9bd9e57e-e4b7-4a81-9d61-960cad0f654e
status: experimental
description: Detects potential processes activity of Jump Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Jump Desktop
level: medium
```
