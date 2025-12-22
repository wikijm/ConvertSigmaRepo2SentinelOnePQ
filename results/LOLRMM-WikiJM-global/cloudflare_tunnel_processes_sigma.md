```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "cloudflared.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CloudFlare Tunnel RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - cloudflared.exe
  condition: selection
id: 2f96065e-f2f6-4f4a-8567-4a79e03eeb5f
status: experimental
description: Detects potential processes activity of CloudFlare Tunnel RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CloudFlare Tunnel
level: medium
```
