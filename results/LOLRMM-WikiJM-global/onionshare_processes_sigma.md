```sql
// Translated content (automatically translated on 20-07-2025 01:56:05):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*\onionshare*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Onionshare RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\onionshare*.exe'
  condition: selection
id: 47582285-6b9b-4f48-a5ad-f60b1a9da608
status: experimental
description: Detects potential processes activity of Onionshare RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Onionshare
level: medium
```
