```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\VMwareXferlogs.exe" and (not tgt.process.image.path contains "C:\Program Files\VMware\")))
```


# Original Sigma Rule:
```yaml
title: DLL Sideloading by VMware Xfer Utility
id: ebea773c-a8f1-42ad-a856-00cb221966e8
status: test
description: Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
references:
    - https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-02
tags:
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\VMwareXferlogs.exe'
    filter: # VMware might be installed in another path so update the rule accordingly
        Image|startswith: 'C:\Program Files\VMware\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
