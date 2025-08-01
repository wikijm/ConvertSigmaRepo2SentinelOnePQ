```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/tmp/")
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Execution From Tmp Folder
id: 312b42b1-bded-4441-8b58-163a3af58775
status: test
description: Detects a potentially suspicious execution of a process located in the '/tmp/' folder
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|startswith: '/tmp/'
    condition: selection
falsepositives:
    - Unknown
level: high
```
