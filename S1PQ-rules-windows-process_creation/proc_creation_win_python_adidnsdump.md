```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\python.exe" and tgt.process.cmdline contains "adidnsdump"))
```


# Original Sigma Rule:
```yaml
title: PUA - Adidnsdump Execution
id: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160
status: test
description: |
    This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
    Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump
author: frack113
date: 2022-01-01
modified: 2023-02-21
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\python.exe'
        CommandLine|contains: 'adidnsdump'
    condition: selection
falsepositives:
    - Unknown
level: low
```
