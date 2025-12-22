```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\GoogleDriveFS.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Google Drive RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\GoogleDriveFS.exe'
  condition: selection
id: b8b3c2a8-ac0d-4384-aaa0-ca4866c1ba1d
status: experimental
description: Detects potential processes activity of Google Drive RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Google Drive
level: medium
```
