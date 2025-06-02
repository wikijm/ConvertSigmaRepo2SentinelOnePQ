```sql
// Translated content (automatically translated on 02-06-2025 00:55:03):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\Solar-PuTTY.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Solar-PuTTY RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Solar-PuTTY.exe'
  condition: selection
id: f97f2561-15d9-4649-a34c-ca25cb71ad2e
status: experimental
description: Detects potential processes activity of Solar-PuTTY RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Solar-PuTTY
level: medium
```
