```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/touch" and tgt.process.cmdline contains " -t " and tgt.process.cmdline contains ".service"))
```


# Original Sigma Rule:
```yaml
title: Touch Suspicious Service File
id: 31545105-3444-4584-bebf-c466353230d2
status: test
description: Detects usage of the "touch" process in service file.
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-11
tags:
    - attack.defense-evasion
    - attack.t1070.006
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/touch'
        CommandLine|contains: ' -t '
        CommandLine|endswith: '.service'
    condition: selection
falsepositives:
    - Admin changing date of files.
level: medium
```
