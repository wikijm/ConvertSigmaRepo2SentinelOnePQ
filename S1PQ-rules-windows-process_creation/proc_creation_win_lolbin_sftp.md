```sql
// Translated content (automatically translated on 02-07-2025 02:07:36):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\sftp.exe" and (tgt.process.cmdline contains " -D .." or tgt.process.cmdline contains " -D C:\")))
```


# Original Sigma Rule:
```yaml
title: Use Of The SFTP.EXE Binary As A LOLBIN
id: a85ffc3a-e8fd-4040-93bf-78aff284d801
status: test
description: Detects the usage of the "sftp.exe" binary as a LOLBIN by abusing the "-D" flag
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/264
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-10
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sftp.exe' # The "sftp.exe" located in the OpenSSH directory has no OriginalFileName :(
        CommandLine|contains:
            # Since "-D" is a valid flag for other usage we assume the user is going to enter a path
            # Either a full one like "C:\Windows\System32\calc.exe" or a relative one "..\..\..\Windows\System32\calc.exe"
            # In my testing you can't execute direct binaries by their name via this method (if you found a way please update the rule)
            - ' -D ..'
            - ' -D C:\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
