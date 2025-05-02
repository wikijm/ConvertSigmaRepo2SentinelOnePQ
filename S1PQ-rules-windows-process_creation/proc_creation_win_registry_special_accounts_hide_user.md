```sql
// Translated content (automatically translated on 02-05-2025 02:00:24):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\reg.exe" and (tgt.process.cmdline contains "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" and tgt.process.cmdline contains "add" and tgt.process.cmdline contains "/v" and tgt.process.cmdline contains "/d 0")))
```


# Original Sigma Rule:
```yaml
title: Hiding User Account Via SpecialAccounts Registry Key - CommandLine
id: 9ec9fb1b-e059-4489-9642-f270c207923d
related:
    - id: f8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd
      type: similar
status: experimental
description: |
    Detects changes to the registry key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" where the value is set to "0" in order to hide user account from being listed on the logon screen.
references:
    - https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/
    - https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion/
    - https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: '@Kostastsale, TheDFIRReport'
date: 2022-05-14
modified: 2024-08-23
tags:
    - attack.t1564.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
            - 'add'
            - '/v'
            - '/d 0'
    condition: selection
falsepositives:
    - System administrator activities
level: medium
```
