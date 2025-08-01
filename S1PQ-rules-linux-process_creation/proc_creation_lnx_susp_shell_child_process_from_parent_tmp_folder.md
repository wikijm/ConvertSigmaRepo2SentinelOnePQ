```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.image.path contains "/tmp/" and (tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/csh" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/fish" or tgt.process.image.path contains "/ksh" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/zsh")))
```


# Original Sigma Rule:
```yaml
title: Shell Execution Of Process Located In Tmp Directory
id: 2fade0b6-7423-4835-9d4f-335b39b83867
status: test
description: Detects execution of shells from a parent process located in a temporary (/tmp) directory
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
        ParentImage|startswith: '/tmp/'
        Image|endswith:
            - '/bash'
            - '/csh'
            - '/dash'
            - '/fish'
            - '/ksh'
            - '/sh'
            - '/zsh'
    condition: selection
falsepositives:
    - Unknown
level: high
```
