```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\Dropbox.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Dropbox RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Dropbox.exe'
  condition: selection
id: 6300b5e7-3e3c-4c2b-8767-c92fb412f065
status: experimental
description: Detects potential processes activity of Dropbox RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Dropbox
level: medium
```
