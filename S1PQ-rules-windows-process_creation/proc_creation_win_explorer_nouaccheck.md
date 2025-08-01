```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\explorer.exe" and tgt.process.cmdline contains "/NOUACCHECK") and (not (src.process.cmdline="C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule" or src.process.image.path="C:\Windows\System32\svchost.exe"))))
```


# Original Sigma Rule:
```yaml
title: Explorer NOUACCHECK Flag
id: 534f2ef7-e8a2-4433-816d-c91bccde289b
status: test
description: Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks
references:
    - https://twitter.com/ORCA6665/status/1496478087244095491
author: Florian Roth (Nextron Systems)
date: 2022-02-23
modified: 2022-04-21
tags:
    - attack.defense-evasion
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\explorer.exe'
        CommandLine|contains: '/NOUACCHECK'
    filter_dc_logon:
        - ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
        - ParentImage: 'C:\Windows\System32\svchost.exe' # coarse filter needed for ID 4688 Events
    condition: selection and not 1 of filter_*
falsepositives:
    - Domain Controller User Logon
    - Unknown how many legitimate software products use that method
level: high
```
