```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "rundll32.exe" and (tgt.process.cmdline contains ".sys," or tgt.process.cmdline contains ".sys ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Rundll32 Activity Invoking Sys File
id: 731231b9-0b5d-4219-94dd-abb6959aa7ea
status: test
description: Detects suspicious process related to rundll32 based on command line that includes a *.sys file as seen being used by UNC2452
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
author: Florian Roth (Nextron Systems)
date: 2021-03-05
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 'rundll32.exe'
    selection2:
        CommandLine|contains:
            - '.sys,'
            - '.sys '
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
