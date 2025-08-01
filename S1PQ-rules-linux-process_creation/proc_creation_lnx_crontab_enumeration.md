```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/crontab" and tgt.process.cmdline contains " -l"))
```


# Original Sigma Rule:
```yaml
title: Crontab Enumeration
id: 403ed92c-b7ec-4edd-9947-5b535ee12d46
status: test
description: Detects usage of crontab to list the tasks of the user
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.discovery
    - attack.t1007
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/crontab'
        CommandLine|contains: ' -l'
    condition: selection
falsepositives:
    - Legitimate use of crontab
level: low
```
