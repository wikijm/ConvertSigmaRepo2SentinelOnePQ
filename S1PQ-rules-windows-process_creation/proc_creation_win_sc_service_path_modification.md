```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\sc.exe" and (tgt.process.cmdline contains "config" and tgt.process.cmdline contains "binPath") and (tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "cmd " or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "svchost" or tgt.process.cmdline contains "dllhost" or tgt.process.cmdline contains "cmd.exe /c" or tgt.process.cmdline contains "cmd.exe /k" or tgt.process.cmdline contains "cmd.exe /r" or tgt.process.cmdline contains "cmd /c" or tgt.process.cmdline contains "cmd /k" or tgt.process.cmdline contains "cmd /r" or tgt.process.cmdline contains "C:\\Users\\Public" or tgt.process.cmdline contains "\\Downloads\\" or tgt.process.cmdline contains "\\Desktop\\" or tgt.process.cmdline contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or tgt.process.cmdline contains "C:\\Windows\\TEMP\\" or tgt.process.cmdline contains "\\AppData\\Local\\Temp")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Service Path Modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
status: test
description: Detects service path modification via the "sc" binary to a suspicious command or path
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
author: Victor Sergeev, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-21
modified: 2022-11-18
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
        CommandLine|contains:
            # Add more suspicious commands or binaries
            - 'powershell'
            - 'cmd '
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'rundll32'
            - 'svchost'
            - 'dllhost'
            - 'cmd.exe /c'
            - 'cmd.exe /k'
            - 'cmd.exe /r'
            - 'cmd /c'
            - 'cmd /k'
            - 'cmd /r'
            # Add more suspicious paths
            - 'C:\Users\Public'
            - '\Downloads\'
            - '\Desktop\'
            - '\Microsoft\Windows\Start Menu\Programs\Startup\'
            - 'C:\Windows\TEMP\'
            - '\AppData\Local\Temp'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
