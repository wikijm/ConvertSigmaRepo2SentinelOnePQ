```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/csh" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/fish" or tgt.process.image.path contains "/ksh" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/zsh") and tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "/tmp/"))
```


# Original Sigma Rule:
```yaml
title: Execution Of Script Located In Potentially Suspicious Directory
id: 30bcce26-51c5-49f2-99c8-7b59e3af36c7
status: test
description: Detects executions of scripts located in potentially suspicious locations such as "/tmp" via a shell such as "bash", "sh", etc.
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
    selection_img:
        Image|endswith:
            - '/bash'
            - '/csh'
            - '/dash'
            - '/fish'
            - '/ksh'
            - '/sh'
            - '/zsh'
    selection_flag:
        CommandLine|contains: ' -c '
    selection_paths:
        # Note: Add more suspicious paths
        CommandLine|contains: '/tmp/'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
