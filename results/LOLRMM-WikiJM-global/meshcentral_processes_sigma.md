```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*meshcentral*.exe" or src.process.image.path="*mesh*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - meshcentral*.exe
    - mesh*.exe
  condition: selection
id: 86eb4e28-14e7-4dfa-8d6d-3e35db4f7d2e
status: experimental
description: Detects potential processes activity of MeshCentral RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MeshCentral
level: medium
```
