```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\SmarTTY.exe")
```


# Original Sigma Rule:
```yaml
title: Potential SmarTTY RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\SmarTTY.exe'
  condition: selection
id: adb38ae5-f722-4cf0-92ea-881354509552
status: experimental
description: Detects potential processes activity of SmarTTY RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SmarTTY
level: medium
```
