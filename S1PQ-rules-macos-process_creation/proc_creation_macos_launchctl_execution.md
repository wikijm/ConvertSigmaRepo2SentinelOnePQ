```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/launchctl" and (tgt.process.cmdline contains "submit" or tgt.process.cmdline contains "load" or tgt.process.cmdline contains "start")))
```


# Original Sigma Rule:
```yaml
title: Launch Agent/Daemon Execution Via Launchctl
id: ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e
status: test
description: Detects the execution of programs as Launch Agents or Launch Daemons using launchctl on macOS.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1569.001/T1569.001.md
    - https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/
    - https://www.welivesecurity.com/2020/07/16/mac-cryptocurrency-trading-application-rebranded-bundled-malware/
    - https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
    - https://www.loobins.io/binaries/launchctl/
author: Pratinav Chandra
date: 2024-05-13
tags:
    - attack.execution
    - attack.persistence
    - attack.t1569.001
    - attack.t1543.001
    - attack.t1543.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/launchctl'
        CommandLine|contains:
            - 'submit'
            - 'load'
            - 'start'
    condition: selection
falsepositives:
    - Legitimate administration activities is expected to trigger false positives. Investigate the command line being passed to determine if the service or launch agent are suspicious.
level: medium
```
