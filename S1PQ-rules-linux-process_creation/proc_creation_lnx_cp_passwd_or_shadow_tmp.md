```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/cp" and tgt.process.cmdline contains "/tmp/" and (tgt.process.cmdline contains "passwd" or tgt.process.cmdline contains "shadow")))
```


# Original Sigma Rule:
```yaml
title: Copy Passwd Or Shadow From TMP Path
id: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
status: test
description: Detects when the file "passwd" or "shadow" is copied from tmp path
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-31
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_img:
        Image|endswith: '/cp'
    selection_path:
        CommandLine|contains: '/tmp/'
    selection_file:
        CommandLine|contains:
            - 'passwd'
            - 'shadow'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
