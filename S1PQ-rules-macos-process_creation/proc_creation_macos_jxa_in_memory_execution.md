```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.cmdline contains "osascript" and tgt.process.cmdline contains " -e " and tgt.process.cmdline contains "eval" and tgt.process.cmdline contains "NSData.dataWithContentsOfURL") and ((tgt.process.cmdline contains " -l " and tgt.process.cmdline contains "JavaScript") or tgt.process.cmdline contains ".js"))) | columns tgt.process.cmdline
```


# Original Sigma Rule:
```yaml
title: JXA In-memory Execution Via OSAScript
id: f1408a58-0e94-4165-b80a-da9f96cf6fc3
related:
    - id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
      type: derived
status: test
description: Detects possible malicious execution of JXA in-memory via OSAScript
references:
    - https://redcanary.com/blog/applescript/
author: Sohan G (D4rkCiph3r)
date: 2023-01-31
tags:
    - attack.t1059.002
    - attack.t1059.007
    - attack.execution
logsource:
    product: macos
    category: process_creation
detection:
    selection_main:
        CommandLine|contains|all:
            - 'osascript'
            - ' -e '
            - 'eval'
            - 'NSData.dataWithContentsOfURL'
    selection_js:
        - CommandLine|contains|all:
              - ' -l '
              - 'JavaScript'
        - CommandLine|contains: '.js'
    condition: all of selection_*
fields:
    - CommandLine
falsepositives:
    - Unknown
level: high
```
