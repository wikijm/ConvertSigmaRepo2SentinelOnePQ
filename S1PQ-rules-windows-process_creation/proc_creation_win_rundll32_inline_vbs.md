```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "rundll32.exe" and tgt.process.cmdline contains "Execute" and tgt.process.cmdline contains "RegRead" and tgt.process.cmdline contains "window.close"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Rundll32 Invoking Inline VBScript
id: 1cc50f3f-1fc8-4acf-b2e9-6f172e1fdebd
status: test
description: Detects suspicious process related to rundll32 based on command line that invokes inline VBScript as seen being used by UNC2452
references:
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/
author: Florian Roth (Nextron Systems)
date: 2021-03-05
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'rundll32.exe'
            - 'Execute'
            - 'RegRead'
            - 'window.close'
    condition: selection
falsepositives:
    - Unknown
level: high
```
