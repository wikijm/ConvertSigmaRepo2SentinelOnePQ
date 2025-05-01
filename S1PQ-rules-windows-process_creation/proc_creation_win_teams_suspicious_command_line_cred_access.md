```sql
// Translated content (automatically translated on 01-05-2025 02:08:55):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\Microsoft\Teams\Cookies" or tgt.process.cmdline contains "\Microsoft\Teams\Local Storage\leveldb") and (not tgt.process.image.path contains "\Microsoft\Teams\current\Teams.exe")))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Command Targeting Teams Sensitive Files
id: d2eb17db-1d39-41dc-b57f-301f6512fa75
status: test
description: |
    Detects a commandline containing references to the Microsoft Teams database or cookies files from a process other than Teams.
    The database might contain authentication tokens and other sensitive information about the logged in accounts.
references:
    - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
    - https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
author: '@SerkinValery'
date: 2022-09-16
modified: 2023-12-18
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '\Microsoft\Teams\Cookies'
            - '\Microsoft\Teams\Local Storage\leveldb'
    filter_main_legit_locations:
        Image|endswith: '\Microsoft\Teams\current\Teams.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
