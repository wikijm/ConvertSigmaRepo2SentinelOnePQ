```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "UserInitMprLogonScript")
```


# Original Sigma Rule:
```yaml
title: Potential Persistence Via Logon Scripts - CommandLine
id: 21d856f9-9281-4ded-9377-51a1a6e2a432
related:
    - id: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
      type: derived
status: test
description: Detects the addition of a new LogonScript to the registry value "UserInitMprLogonScript" for potential persistence
references:
    - https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
author: Tom Ueltschi (@c_APT_ure)
date: 2019-01-12
modified: 2023-06-09
tags:
    - attack.persistence
    - attack.t1037.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'UserInitMprLogonScript'
    condition: selection
falsepositives:
    - Legitimate addition of Logon Scripts via the command line by administrators or third party tools
level: high
```
