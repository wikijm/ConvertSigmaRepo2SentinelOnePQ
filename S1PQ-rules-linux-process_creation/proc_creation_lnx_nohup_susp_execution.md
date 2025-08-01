```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/nohup" and tgt.process.cmdline contains "/tmp/"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Nohup Execution
id: 457df417-8b9d-4912-85f3-9dbda39c3645
related:
    - id: e4ffe466-6ff8-48d4-94bd-e32d1a6061e2
      type: derived
status: test
description: Detects execution of binaries located in potentially suspicious locations via "nohup"
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.execution
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/nohup'
        CommandLine|contains: '/tmp/'
    condition: selection
falsepositives:
    - Unknown
level: high
```
