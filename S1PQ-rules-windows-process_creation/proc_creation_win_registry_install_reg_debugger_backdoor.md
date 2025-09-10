```sql
// Translated content (automatically translated on 10-09-2025 01:51:41):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\CurrentVersion\\Image File Execution Options\\" and (tgt.process.cmdline contains "sethc.exe" or tgt.process.cmdline contains "utilman.exe" or tgt.process.cmdline contains "osk.exe" or tgt.process.cmdline contains "magnify.exe" or tgt.process.cmdline contains "narrator.exe" or tgt.process.cmdline contains "displayswitch.exe" or tgt.process.cmdline contains "atbroker.exe" or tgt.process.cmdline contains "HelpPane.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Debugger Registration Cmdline
id: ae215552-081e-44c7-805f-be16f975c8a2
status: test
description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
    - https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: 2019-09-06
modified: 2022-08-06
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.008
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: '\CurrentVersion\Image File Execution Options\'
    selection2:
        CommandLine|contains:
            - 'sethc.exe'
            - 'utilman.exe'
            - 'osk.exe'
            - 'magnify.exe'
            - 'narrator.exe'
            - 'displayswitch.exe'
            - 'atbroker.exe'
            - 'HelpPane.exe'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
