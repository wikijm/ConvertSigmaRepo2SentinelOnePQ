```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\sc.exe" and (tgt.process.cmdline contains "create" and tgt.process.cmdline contains "binPath=")) or (tgt.process.cmdline contains "New-Service" and tgt.process.cmdline contains "-BinaryPathName")) and (tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "svchost" or tgt.process.cmdline contains "dllhost" or tgt.process.cmdline contains "cmd " or tgt.process.cmdline contains "cmd.exe /c" or tgt.process.cmdline contains "cmd.exe /k" or tgt.process.cmdline contains "cmd.exe /r" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "C:\Users\Public" or tgt.process.cmdline contains "\Downloads\" or tgt.process.cmdline contains "\Desktop\" or tgt.process.cmdline contains "\Microsoft\Windows\Start Menu\Programs\Startup\" or tgt.process.cmdline contains "C:\Windows\TEMP\" or tgt.process.cmdline contains "\AppData\Local\Temp")))
```


# Original Sigma Rule:
```yaml
title: Suspicious New Service Creation
id: 17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8
related:
    - id: 7fe71fc9-de3b-432a-8d57-8c809efc10ab
      type: derived
status: test
description: Detects creation of a new service via "sc" command or the powershell "new-service" cmdlet with suspicious binary paths
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-14
modified: 2022-11-18
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'create'
            - 'binPath='
    selection_posh:
        CommandLine|contains|all:
            - 'New-Service'
            - '-BinaryPathName'
    susp_binpath:
        CommandLine|contains:
            # Add more suspicious commands or binaries
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'svchost'
            - 'dllhost'
            - 'cmd '
            - 'cmd.exe /c'
            - 'cmd.exe /k'
            - 'cmd.exe /r'
            - 'rundll32'
            # Add more suspicious paths
            - 'C:\Users\Public'
            - '\Downloads\'
            - '\Desktop\'
            - '\Microsoft\Windows\Start Menu\Programs\Startup\'
            - 'C:\Windows\TEMP\'
            - '\AppData\Local\Temp'
    condition: 1 of selection* and susp_binpath
falsepositives:
    - Unlikely
level: high
```
