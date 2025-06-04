```sql
// Translated content (automatically translated on 04-06-2025 00:53:25):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*AcronisCyberProtectConnectQuickAssist*.exe" or src.process.image.path contains "AcronisCyberProtectConnectAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Acronic Cyber Protect (Remotix) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - AcronisCyberProtectConnectQuickAssist*.exe
    - AcronisCyberProtectConnectAgent.exe
  condition: selection
id: 9b9647ab-97cc-4c7c-8540-5c1c1c8000c4
status: experimental
description: Detects potential processes activity of Acronic Cyber Protect (Remotix)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Acronic Cyber Protect (Remotix)
level: medium
```
