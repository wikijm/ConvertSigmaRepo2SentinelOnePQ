```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "copy " and tgt.process.cmdline contains "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"))
```


# Original Sigma Rule:
```yaml
title: Copy From VolumeShadowCopy Via Cmd.EXE
id: c73124a7-3e89-44a3-bdc1-25fe4df754b1
status: test
description: Detects the execution of the builtin "copy" command that targets a shadow copy (sometimes used to copy registry hives that are in use)
references:
    - https://twitter.com/vxunderground/status/1423336151860002816?s=20
    - https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection
    - https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/
author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
date: 2021-08-09
modified: 2023-03-07
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM\
        # There is an additional "\" to escape the special "?"
        CommandLine|contains|all:
            - 'copy '
            - '\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy'
    condition: selection
falsepositives:
    - Backup scenarios using the commandline
level: high
```
