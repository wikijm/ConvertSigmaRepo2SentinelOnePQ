```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "rundll32" and tgt.process.cmdline contains "apphelp.dll") and (tgt.process.cmdline contains "ShimFlushCache" or tgt.process.cmdline contains "#250")) or ((tgt.process.cmdline contains "rundll32" and tgt.process.cmdline contains "kernel32.dll") and (tgt.process.cmdline contains "BaseFlushAppcompatCache" or tgt.process.cmdline contains "#46"))))
```


# Original Sigma Rule:
```yaml
title: ShimCache Flush
id: b0524451-19af-4efa-a46f-562a977f792e
status: stable
description: Detects actions that clear the local ShimCache and remove forensic evidence
references:
    - https://medium.com/@blueteamops/shimcache-flush-89daff28d15e
author: Florian Roth (Nextron Systems)
date: 2021-02-01
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection1a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'apphelp.dll'
    selection1b:
        CommandLine|contains:
            - 'ShimFlushCache'
            - '#250'
    selection2a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'kernel32.dll'
    selection2b:
        CommandLine|contains:
            - 'BaseFlushAppcompatCache'
            - '#46'
    condition: ( selection1a and selection1b ) or ( selection2a and selection2b )
falsepositives:
    - Unknown
level: high
```
