```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\schtasks.exe" and (tgt.process.cmdline contains " /Change " and tgt.process.cmdline contains " /TN ")) and (tgt.process.cmdline contains "\\AppData\\Local\\Temp" or tgt.process.cmdline contains "\\AppData\\Roaming\\" or tgt.process.cmdline contains "\\Users\\Public\\" or tgt.process.cmdline contains "\\WINDOWS\\Temp\\" or tgt.process.cmdline contains "\\Desktop\\" or tgt.process.cmdline contains "\\Downloads\\" or tgt.process.cmdline contains "\\Temporary Internet" or tgt.process.cmdline contains "C:\\ProgramData\\" or tgt.process.cmdline contains "C:\\Perflogs\\" or tgt.process.cmdline contains "%ProgramData%" or tgt.process.cmdline contains "%appdata%" or tgt.process.cmdline contains "%comspec%" or tgt.process.cmdline contains "%localappdata%") and (tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "cmd /c " or tgt.process.cmdline contains "cmd /k " or tgt.process.cmdline contains "cmd /r " or tgt.process.cmdline contains "cmd.exe /c " or tgt.process.cmdline contains "cmd.exe /k " or tgt.process.cmdline contains "cmd.exe /r " or tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "certutil" or tgt.process.cmdline contains "bitsadmin" or tgt.process.cmdline contains "bash.exe" or tgt.process.cmdline contains "bash " or tgt.process.cmdline contains "scrcons" or tgt.process.cmdline contains "wmic " or tgt.process.cmdline contains "wmic.exe" or tgt.process.cmdline contains "forfiles" or tgt.process.cmdline contains "scriptrunner" or tgt.process.cmdline contains "hh.exe" or tgt.process.cmdline contains "hh ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Modification Of Scheduled Tasks
id: 1c0e41cd-21bb-4433-9acc-4a2cd6367b9b
related:
    - id: 614cf376-6651-47c4-9dcc-6b9527f749f4 # Security-Audting Eventlog
      type: similar
status: test
description: |
    Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
    Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
    Instead they modify the task after creation to include their malicious payload
references:
    - Internal Research
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-28
modified: 2022-11-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /Change '
            - ' /TN '
    selection_susp_locations:
        CommandLine|contains:
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\WINDOWS\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Temporary Internet'
            - 'C:\ProgramData\'
            - 'C:\Perflogs\'
            - '%ProgramData%'
            - '%appdata%'
            - '%comspec%'
            - '%localappdata%'
    selection_susp_images:
        CommandLine|contains:
            - 'regsvr32'
            - 'rundll32'
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'certutil'
            - 'bitsadmin'
            - 'bash.exe'
            - 'bash '
            - 'scrcons'
            - 'wmic '
            - 'wmic.exe'
            - 'forfiles'
            - 'scriptrunner'
            - 'hh.exe'
            - 'hh '
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
