```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "if(0){{{0}}}' -f $(0 -as [char]) +" or tgt.process.cmdline contains "#<NULL>"))
```


# Original Sigma Rule:
```yaml
title: Potential AMSI Bypass Using NULL Bits
id: 92a974db-ab84-457f-9ec0-55db83d7a825
related:
    - id: fa2559c8-1197-471d-9cdd-05a0273d4522
      type: similar
status: test
description: Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities
references:
    - https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-bypass-using-null-bits-satoshi
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-04
modified: 2023-05-09
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "if(0){{{0}}}' -f $(0 -as [char]) +"
            - "#<NULL>"
    condition: selection
falsepositives:
    - Unknown
level: medium
```
