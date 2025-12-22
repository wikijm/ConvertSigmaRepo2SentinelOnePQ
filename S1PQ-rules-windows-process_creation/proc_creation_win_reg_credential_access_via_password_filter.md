```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" and tgt.process.cmdline contains "scecli\\0" and tgt.process.cmdline contains "reg add"))
```


# Original Sigma Rule:
```yaml
title: Dropping Of Password Filter DLL
id: b7966f4a-b333-455b-8370-8ca53c229762
status: test
description: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
references:
    - https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
    - https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter
author: Sreeman
date: 2020-10-29
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.credential-access
    - attack.t1556.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline:
        CommandLine|contains|all:
            - 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
            - 'scecli\0*'
            - 'reg add'
    condition: selection_cmdline
falsepositives:
    - Unknown
level: medium
```
