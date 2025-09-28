```sql
// Translated content (automatically translated on 28-09-2025 02:03:26):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "eyJ0eXAiOi" or tgt.process.cmdline contains "eyJhbGciOi" or tgt.process.cmdline contains " eyJ0eX" or tgt.process.cmdline contains " \"eyJ0eX\"" or tgt.process.cmdline contains " 'eyJ0eX'" or tgt.process.cmdline contains " eyJhbG" or tgt.process.cmdline contains " \"eyJhbG\"" or tgt.process.cmdline contains " 'eyJhbG'"))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious JWT Token Search Via CLI
id: 6d3a3952-6530-44a3-8554-cf17c116c615
status: test
description: |
    Detects possible search for JWT tokens via CLI by looking for the string "eyJ0eX" or "eyJhbG".
    This string is used as an anchor to look for the start of the JWT token used by microsoft office and similar apps.
references:
    - https://mrd0x.com/stealing-tokens-from-office-applications/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-25
modified: 2024-10-06
tags:
    - attack.credential-access
    - attack.t1528
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'eyJ0eXAiOi' # {"typ":
            - 'eyJhbGciOi' # {"alg":
            - ' eyJ0eX'
            - ' "eyJ0eX"'
            - " 'eyJ0eX'"
            - ' eyJhbG'
            - ' "eyJhbG"'
            - " 'eyJhbG'"
    condition: selection
falsepositives:
    - Unknown
level: medium
```
