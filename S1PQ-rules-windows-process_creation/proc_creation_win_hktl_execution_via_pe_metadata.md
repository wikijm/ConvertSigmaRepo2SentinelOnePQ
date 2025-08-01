```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.publisher="Cube0x0")
```


# Original Sigma Rule:
```yaml
title: Hacktool Execution - PE Metadata
id: 37c1333a-a0db-48be-b64b-7393b2386e3b
status: test
description: Detects the execution of different Windows based hacktools via PE metadata (company, product, etc.) even if the files have been renamed
references:
    - https://github.com/cube0x0
    - https://www.virustotal.com/gui/search/metadata%253ACube0x0/files
author: Florian Roth (Nextron Systems)
date: 2022-04-27
modified: 2024-01-15
tags:
    - attack.credential-access
    - attack.resource-development
    - attack.t1588.002
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Company: 'Cube0x0' # Detects the use of tools created by a well-known hacktool producer named "Cube0x0", which includes his handle in all binaries as company information in the PE headers (SharpPrintNightmare, KrbRelay, SharpMapExec, etc.)
    condition: selection
falsepositives:
    - Unlikely
level: high
```
