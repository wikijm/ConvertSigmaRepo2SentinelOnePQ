```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "winrm" and ((tgt.process.cmdline contains "format:pretty" or tgt.process.cmdline contains "format:\"pretty\"" or tgt.process.cmdline contains "format:\"text\"" or tgt.process.cmdline contains "format:text") and (not (tgt.process.image.path contains "C:\Windows\System32\" or tgt.process.image.path contains "C:\Windows\SysWOW64\")))))
```


# Original Sigma Rule:
```yaml
title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
id: 074e0ded-6ced-4ebd-8b4d-53f55908119d
status: test
description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
references:
    - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
author: Julia Fomina, oscd.community
date: 2020-10-06
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    contains_format_pretty_arg:
        CommandLine|contains:
            - 'format:pretty'
            - 'format:"pretty"'
            - 'format:"text"'
            - 'format:text'
    image_from_system_folder:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    contains_winrm:
        CommandLine|contains: 'winrm'
    condition: contains_winrm and (contains_format_pretty_arg and not image_from_system_folder)
falsepositives:
    - Unlikely
level: medium
```
