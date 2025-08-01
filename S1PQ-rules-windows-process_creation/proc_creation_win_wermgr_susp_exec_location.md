```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\wermgr.exe" and (not (tgt.process.image.path contains "C:\Windows\System32\" or tgt.process.image.path contains "C:\Windows\SysWOW64\" or tgt.process.image.path contains "C:\Windows\WinSxS\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution Location Of Wermgr.EXE
id: 5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5
related:
    - id: 396f6630-f3ac-44e3-bfc8-1b161bc00c4e
      type: similar
status: test
description: Detects suspicious Windows Error Reporting manager (wermgr.exe) execution location.
references:
    - https://www.trendmicro.com/en_us/research/22/j/black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-coba.html
    - https://www.echotrail.io/insights/search/wermgr.exe
    - https://github.com/binderlabs/DirCreate2System
author: Florian Roth (Nextron Systems)
date: 2022-10-14
modified: 2023-08-23
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wermgr.exe'
    filter_main_legit_location:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
