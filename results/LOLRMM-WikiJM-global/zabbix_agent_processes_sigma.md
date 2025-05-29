```sql
// Translated content (automatically translated on 29-05-2025 01:39:17):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*zabbix_agent*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Zabbix Agent RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - zabbix_agent*.exe
  condition: selection
id: 415d6e06-ca39-4cbf-9a23-c14d720f92e4
status: experimental
description: Detects potential processes activity of Zabbix Agent RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Zabbix Agent
level: medium
```
