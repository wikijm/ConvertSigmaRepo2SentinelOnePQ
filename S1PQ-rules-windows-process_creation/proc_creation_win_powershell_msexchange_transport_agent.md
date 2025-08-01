```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "Install-TransportAgent") | columns AssemblyPath
```


# Original Sigma Rule:
```yaml
title: MSExchange Transport Agent Installation
id: 83809e84-4475-4b69-bc3e-4aad8568612f
related:
    - id: 83809e84-4475-4b69-bc3e-4aad8568612f
      type: similar
status: test
description: Detects the Installation of a Exchange Transport Agent
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=7
author: Tobias Michalski (Nextron Systems)
date: 2021-06-08
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.t1505.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'Install-TransportAgent'
    condition: selection
fields:
    - AssemblyPath
falsepositives:
    - Legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
level: medium
```
