```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "find " or tgt.process.cmdline contains "find.exe" or tgt.process.cmdline contains "findstr" or tgt.process.cmdline contains "select-string " or tgt.process.cmdline contains "strings") and (tgt.process.cmdline contains "eyJ0eXAiOi" or tgt.process.cmdline contains "eyJhbGciOi" or tgt.process.cmdline contains " eyJ0eX" or tgt.process.cmdline contains " \"eyJ0eX\"" or tgt.process.cmdline contains " 'eyJ0eX'" or tgt.process.cmdline contains " eyJhbG" or tgt.process.cmdline contains " \"eyJhbG\"" or tgt.process.cmdline contains " 'eyJhbG'")))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious JWT Token Search Via CLI
id: 6d3a3952-6530-44a3-8554-cf17c116c615
status: test
description: |
    Detects potentially suspicious search for JWT tokens via CLI by looking for the string "eyJ0eX" or "eyJhbG".
    JWT tokens are often used for access-tokens across various applications and services like Microsoft 365, Azure, AWS, Google Cloud, and others.
    Threat actors may search for these tokens to steal them for lateral movement or privilege escalation.
references:
    - https://mrd0x.com/stealing-tokens-from-office-applications/
    - https://www.scip.ch/en/?labs.20240523
author: Nasreddine Bencherchali (Nextron Systems), kagebunsher
date: 2022-10-25
modified: 2025-10-21
tags:
    - attack.credential-access
    - attack.t1528
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        CommandLine|contains:
            - 'find '
            - 'find.exe'
            - 'findstr'
            - 'select-string '
            - 'strings'
    selection_jwt_string:
        CommandLine|contains:
            - 'eyJ0eXAiOi' # {"typ":
            - 'eyJhbGciOi' # {"alg":
            - ' eyJ0eX'
            - ' "eyJ0eX"'
            - " 'eyJ0eX'"
            - ' eyJhbG'
            - ' "eyJhbG"'
            - " 'eyJhbG'"
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
