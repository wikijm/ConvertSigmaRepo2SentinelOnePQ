```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\BvSshServer-Inst.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Bitvise SSH Server RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\BvSshServer-Inst.exe'
  condition: selection
id: 3cae538e-c158-40e4-9ec0-9e49d92a63c4
status: experimental
description: Detects potential processes activity of Bitvise SSH Server RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Bitvise SSH Server
level: medium
```
