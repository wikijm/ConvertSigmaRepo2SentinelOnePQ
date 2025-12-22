```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((src.process.image.path contains "/applet" or src.process.image.path contains "/osascript") and tgt.process.cmdline contains "osacompile"))
```


# Original Sigma Rule:
```yaml
title: Osacompile Execution By Potentially Suspicious Applet/Osascript
id: a753a6af-3126-426d-8bd0-26ebbcb92254
status: test
description: Detects potential suspicious applet or osascript executing "osacompile".
references:
    - https://redcanary.com/blog/mac-application-bundles/
author: Sohan G (D4rkCiph3r), Red Canary (Idea)
date: 2023-04-03
tags:
    - attack.execution
    - attack.t1059.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|endswith:
            - '/applet'
            - '/osascript'
        CommandLine|contains: 'osacompile'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
