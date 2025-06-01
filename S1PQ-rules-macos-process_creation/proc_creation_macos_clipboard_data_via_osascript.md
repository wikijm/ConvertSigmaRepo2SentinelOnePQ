```sql
// Translated content (automatically translated on 01-06-2025 01:41:50):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.cmdline contains "osascript" and tgt.process.cmdline contains " -e " and tgt.process.cmdline contains "clipboard")) | columns tgt.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Clipboard Data Collection Via OSAScript
id: 7794fa3c-edea-4cff-bec7-267dd4770fd7
related:
    - id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
      type: derived
status: test
description: Detects possible collection of data from the clipboard via execution of the osascript binary
references:
    - https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/
author: Sohan G (D4rkCiph3r)
date: 2023-01-31
tags:
    - attack.collection
    - attack.execution
    - attack.t1115
    - attack.t1059.002
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'osascript'
            - ' -e '
            - 'clipboard'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unlikely
level: high
```
