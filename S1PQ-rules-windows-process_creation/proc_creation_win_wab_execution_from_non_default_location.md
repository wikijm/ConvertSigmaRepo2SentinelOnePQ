```sql
// Translated content (automatically translated on 05-06-2025 02:04:50):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\wab.exe" or tgt.process.image.path contains "\wabmig.exe") and (not (tgt.process.image.path contains "C:\Windows\WinSxS\" or tgt.process.image.path contains "C:\Program Files\Windows Mail\" or tgt.process.image.path contains "C:\Program Files (x86)\Windows Mail\"))))
```


# Original Sigma Rule:
```yaml
title: Wab Execution From Non Default Location
id: 395907ee-96e5-4666-af2e-2ca91688e151
status: test
description: Detects execution of wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) from non default locations as seen with bumblebee activity
references:
    - https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bumblebee-loader-cybercrime
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-12
modified: 2022-09-27
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wab.exe'
            - '\wabmig.exe'
    filter:
        Image|startswith:
            - 'C:\Windows\WinSxS\'
            - 'C:\Program Files\Windows Mail\'
            - 'C:\Program Files (x86)\Windows Mail\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
