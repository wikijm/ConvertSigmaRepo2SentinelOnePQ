```sql
// Translated content (automatically translated on 30-06-2025 01:25:55):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/osascript" and (tgt.process.cmdline contains " -e " or tgt.process.cmdline contains ".scpt" or tgt.process.cmdline contains ".js")))
```


# Original Sigma Rule:
```yaml
title: MacOS Scripting Interpreter AppleScript
id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
status: test
description: Detects execution of AppleScript of the macOS scripting language AppleScript.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.002/T1059.002.md
    - https://redcanary.com/blog/applescript/
author: Alejandro Ortuno, oscd.community
date: 2020-10-21
modified: 2023-02-01
tags:
    - attack.execution
    - attack.t1059.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/osascript'
        CommandLine|contains:
            - ' -e '
            - '.scpt'
            - '.js'
    condition: selection
falsepositives:
    - Application installers might contain scripts as part of the installation process.
level: medium
```
