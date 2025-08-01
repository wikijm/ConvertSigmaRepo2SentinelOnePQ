```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\HOSTNAME.EXE")
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution of Hostname
id: 7be5fb68-f9ef-476d-8b51-0256ebece19e
status: test
description: Use of hostname to get information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/hostname
author: frack113
date: 2022-01-01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\HOSTNAME.EXE'
    condition: selection
falsepositives:
    - Unknown
level: low
```
