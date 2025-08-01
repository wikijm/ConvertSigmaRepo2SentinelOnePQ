```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\reg.exe" and (tgt.process.cmdline contains "HKEY_CURRENT_USER\Control Panel\Desktop" or tgt.process.cmdline contains "HKCU\Control Panel\Desktop")) and ((tgt.process.cmdline contains "/v ScreenSaveActive" and tgt.process.cmdline contains "/t REG_SZ" and tgt.process.cmdline contains "/d 1" and tgt.process.cmdline contains "/f") or (tgt.process.cmdline contains "/v ScreenSaveTimeout" and tgt.process.cmdline contains "/t REG_SZ" and tgt.process.cmdline contains "/d " and tgt.process.cmdline contains "/f") or (tgt.process.cmdline contains "/v ScreenSaverIsSecure" and tgt.process.cmdline contains "/t REG_SZ" and tgt.process.cmdline contains "/d 0" and tgt.process.cmdline contains "/f") or (tgt.process.cmdline contains "/v SCRNSAVE.EXE" and tgt.process.cmdline contains "/t REG_SZ" and tgt.process.cmdline contains "/d " and tgt.process.cmdline contains ".scr" and tgt.process.cmdline contains "/f"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious ScreenSave Change by Reg.exe
id: 0fc35fc3-efe6-4898-8a37-0b233339524f
status: test
description: |
    Adversaries may establish persistence by executing malicious content triggered by user inactivity.
    Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.002/T1546.002.md
    - https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
author: frack113
date: 2021-08-19
modified: 2022-06-02
tags:
    - attack.privilege-escalation
    - attack.t1546.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'HKEY_CURRENT_USER\Control Panel\Desktop'
            - 'HKCU\Control Panel\Desktop'
    selection_option_1: # /force Active ScreenSaveActive
        CommandLine|contains|all:
            - '/v ScreenSaveActive'
            - '/t REG_SZ'
            - '/d 1'
            - '/f'
    selection_option_2: # /force  set ScreenSaveTimeout
        CommandLine|contains|all:
            - '/v ScreenSaveTimeout'
            - '/t REG_SZ'
            - '/d '
            - '/f'
    selection_option_3: # /force set ScreenSaverIsSecure
        CommandLine|contains|all:
            - '/v ScreenSaverIsSecure'
            - '/t REG_SZ'
            - '/d 0'
            - '/f'
    selection_option_4: # /force set a .scr
        CommandLine|contains|all:
            - '/v SCRNSAVE.EXE'
            - '/t REG_SZ'
            - '/d '
            - '.scr'
            - '/f'
    condition: selection_reg and 1 of selection_option_*
falsepositives:
    - GPO
level: medium
```
