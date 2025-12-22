```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "process " and tgt.process.cmdline contains "call " and tgt.process.cmdline contains "create ") and (tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "bitsadmin" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "cmd.exe /c " or tgt.process.cmdline contains "cmd.exe /k " or tgt.process.cmdline contains "cmd.exe /r " or tgt.process.cmdline contains "cmd /c " or tgt.process.cmdline contains "cmd /k " or tgt.process.cmdline contains "cmd /r " or tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "pwsh" or tgt.process.cmdline contains "certutil" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "\\Users\\Public\\" or tgt.process.cmdline contains "\\Windows\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Local\\" or tgt.process.cmdline contains "%temp%" or tgt.process.cmdline contains "%tmp%" or tgt.process.cmdline contains "%ProgramData%" or tgt.process.cmdline contains "%appdata%" or tgt.process.cmdline contains "%comspec%" or tgt.process.cmdline contains "%localappdata%")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Created Via Wmic.EXE
id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
related:
    - id: 526be59f-a573-4eea-b5f7-f0973207634d # Generic
      type: derived
status: test
description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
references:
    - https://thedfirreport.com/2020/10/08/ryuks-return/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2020-10-12
modified: 2023-02-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'process '
            - 'call '
            - 'create '
        CommandLine|contains:
            # Add more susupicious paths and binaries as you see fit in your env
            - 'rundll32'
            - 'bitsadmin'
            - 'regsvr32'
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'powershell'
            - 'pwsh'
            - 'certutil'
            - 'cscript'
            - 'wscript'
            - 'mshta'
            - '\Users\Public\'
            - '\Windows\Temp\'
            - '\AppData\Local\'
            - '%temp%'
            - '%tmp%'
            - '%ProgramData%'
            - '%appdata%'
            - '%comspec%'
            - '%localappdata%'
    condition: selection
falsepositives:
    - Unknown
level: high
```
