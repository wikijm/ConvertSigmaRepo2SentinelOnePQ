```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\WmiPrvSE.exe" or src.process.image.path contains "\svchost.exe" or src.process.image.path contains "\dllhost.exe") and (tgt.process.image.path contains "\wab.exe" or tgt.process.image.path contains "\wabmig.exe")) or (src.process.image.path contains "\wab.exe" or src.process.image.path contains "\wabmig.exe")))
```


# Original Sigma Rule:
```yaml
title: Wab/Wabmig Unusual Parent Or Child Processes
id: 63d1ccc0-2a43-4f4b-9289-361b308991ff
status: test
description: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
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
    selection_parent:
        ParentImage|endswith:
            # Add more if known
            - \WmiPrvSE.exe
            - \svchost.exe
            - \dllhost.exe
        Image|endswith:
            - '\wab.exe'
            - '\wabmig.exe' # (Microsoft Address Book Import Tool)
    selection_child:
        # You can add specific suspicious child processes (such as cmd, powershell...) to increase the accuracy
        ParentImage|endswith:
            - '\wab.exe'
            - '\wabmig.exe' # (Microsoft Address Book Import Tool)
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
