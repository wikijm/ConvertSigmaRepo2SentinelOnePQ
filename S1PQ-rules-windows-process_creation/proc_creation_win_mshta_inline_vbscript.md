```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Wscript." and tgt.process.cmdline contains ".Shell" and tgt.process.cmdline contains ".Run"))
```


# Original Sigma Rule:
```yaml
title: Wscript Shell Run In CommandLine
id: 2c28c248-7f50-417a-9186-a85b223010ee
status: test
description: Detects the presence of the keywords "Wscript", "Shell" and "Run" in the command, which could indicate a suspicious activity
references:
    - https://web.archive.org/web/20220830122045/http://blog.talosintelligence.com/2022/08/modernloader-delivers-multiple-stealers.html
    - https://blog.talosintelligence.com/modernloader-delivers-multiple-stealers-cryptominers-and-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-31
modified: 2023-05-15
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Wscript.'
            - '.Shell'
            - '.Run'
    condition: selection
falsepositives:
    - Inline scripting can be used by some rare third party applications or administrators. Investigate and apply additional filters accordingly
level: medium
```
