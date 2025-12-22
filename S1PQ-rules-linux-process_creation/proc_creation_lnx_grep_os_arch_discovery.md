```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/grep" and (tgt.process.cmdline contains "aarch64" or tgt.process.cmdline contains "arm" or tgt.process.cmdline contains "i386" or tgt.process.cmdline contains "i686" or tgt.process.cmdline contains "mips" or tgt.process.cmdline contains "x86_64")))
```


# Original Sigma Rule:
```yaml
title: OS Architecture Discovery Via Grep
id: d27ab432-2199-483f-a297-03633c05bae6
status: test
description: |
    Detects the use of grep to identify information about the operating system architecture. Often combined beforehand with the execution of "uname" or "cat /proc/cpuinfo"
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: linux
detection:
    selection_process:
        Image|endswith: '/grep'
    selection_architecture:
        CommandLine|endswith:
            - 'aarch64'
            - 'arm'
            - 'i386'
            - 'i686'
            - 'mips'
            - 'x86_64'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low
```
