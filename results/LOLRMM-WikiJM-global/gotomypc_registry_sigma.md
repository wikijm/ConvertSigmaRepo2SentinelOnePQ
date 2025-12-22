```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKEY_LOCAL_MACHINE\\WOW6432Node\\Citrix\\GoToMyPc" or registry.keyPath contains "HKEY_LOCAL_MACHINE\\WOW6432Node\\Citrix\\GoToMyPc\\GuestInvite" or registry.keyPath contains "HKEY_CURRENT_USER\\SOFTWARE\\Citrix\\GoToMyPc\\FileTransfer\\history" or registry.keyPath contains "HKEY_USERS\\<SID>\\SOFTWARE\\Citrix\\GoToMyPc\\FileTransfer\\history"))
```


# Original Sigma Rule:
```yaml
title: Potential GoToMyPC RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc
    - HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc\GuestInvite
    - HKEY_CURRENT_USER\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
    - HKEY_USERS\<SID>\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
  condition: selection
id: 19774fdd-89fd-43eb-9871-30c5930f1af4
status: experimental
description: Detects potential registry activity of GoToMyPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoToMyPC
level: medium
```
