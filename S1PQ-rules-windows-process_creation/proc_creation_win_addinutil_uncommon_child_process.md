```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\addinutil.exe" and (not (tgt.process.image.path contains ":\\Windows\\System32\\conhost.exe" or tgt.process.image.path contains ":\\Windows\\System32\\werfault.exe" or tgt.process.image.path contains ":\\Windows\\SysWOW64\\werfault.exe"))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Of AddinUtil.EXE
id: b5746143-59d6-4603-8d06-acbd60e166ee
status: test
description: |
    Detects uncommon child processes of the Add-In deployment cache updating utility (AddInutil.exe) which could be a sign of potential abuse of the binary to proxy execution via a custom Addins.Store payload.
references:
    - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: 2023-09-18
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\addinutil.exe'
    filter_main_werfault:
        Image|endswith:
            - ':\Windows\System32\conhost.exe'
            - ':\Windows\System32\werfault.exe'
            - ':\Windows\SysWOW64\werfault.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
