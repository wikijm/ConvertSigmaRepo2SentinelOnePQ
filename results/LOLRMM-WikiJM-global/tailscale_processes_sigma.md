```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*tailscale-*.exe" or src.process.image.path contains "tailscaled.exe" or src.process.image.path contains "tailscale-ipn.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Tailscale RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tailscale-*.exe
    - tailscaled.exe
    - tailscale-ipn.exe
  condition: selection
id: 0b2d2c36-e382-49d8-982a-9805d7c50f67
status: experimental
description: Detects potential processes activity of Tailscale RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tailscale
level: medium
```
