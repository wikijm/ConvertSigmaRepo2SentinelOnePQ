```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.integrityLevel in ("High","S-1-16-12288")) and (tgt.process.cmdline contains "conhost.exe" and tgt.process.cmdline contains "0xffffffff" and tgt.process.cmdline contains "-ForceV1")))
```


# Original Sigma Rule:
```yaml
title: Suspicious High IntegrityLevel Conhost Legacy Option
id: 3037d961-21e9-4732-b27a-637bcc7bf539
status: test
description: ForceV1 asks for information directly from the kernel space. Conhost connects to the console application. High IntegrityLevel means the process is running with elevated privileges, such as an Administrator context.
references:
    - https://cybercryptosec.medium.com/covid-19-cyber-infection-c615ead7c29
    - https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
    - https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
author: frack113
date: 2022-12-09
modified: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.t1202
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        IntegrityLevel:
            - 'High'
            - 'S-1-16-12288'
        CommandLine|contains|all:
            - 'conhost.exe'
            - '0xffffffff'
            - '-ForceV1'
    condition: selection
falsepositives:
    - Very Likely, including launching cmd.exe via Run As Administrator
level: informational
```
