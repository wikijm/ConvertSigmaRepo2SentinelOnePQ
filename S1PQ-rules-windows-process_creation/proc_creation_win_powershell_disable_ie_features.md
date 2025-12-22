```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -name IEHarden " and tgt.process.cmdline contains " -value 0 ") or (tgt.process.cmdline contains " -name DEPOff " and tgt.process.cmdline contains " -value 1 ") or (tgt.process.cmdline contains " -name DisableFirstRunCustomize " and tgt.process.cmdline contains " -value 2 ")))
```


# Original Sigma Rule:
```yaml
title: Disabled IE Security Features
id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: test
description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
references:
    - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
author: Florian Roth (Nextron Systems)
date: 2020-06-19
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - ' -name IEHarden '
            - ' -value 0 '
    selection2:
        CommandLine|contains|all:
            - ' -name DEPOff '
            - ' -value 1 '
    selection3:
        CommandLine|contains|all:
            - ' -name DisableFirstRunCustomize '
            - ' -value 2 '
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
