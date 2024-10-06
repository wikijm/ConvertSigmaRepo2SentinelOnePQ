```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "eyJ0eXAiOi" or tgt.process.cmdline contains " eyJ0eX" or tgt.process.cmdline contains " \"eyJ0eX\"" or tgt.process.cmdline contains " 'eyJ0eX'"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Office Token Search Via CLI
id: 6d3a3952-6530-44a3-8554-cf17c116c615
status: test
description: Detects possible search for office tokens via CLI by looking for the string "eyJ0eX". This string is used as an anchor to look for the start of the JWT token used by office and similar apps.
references:
    - https://mrd0x.com/stealing-tokens-from-office-applications/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-25
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
            - ' eyJ0eX'
            - ' "eyJ0eX"'
            - " 'eyJ0eX'"
    condition: selection
falsepositives:
    - Unknown
level: medium
```