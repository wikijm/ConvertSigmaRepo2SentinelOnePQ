```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/osascript" and (tgt.process.cmdline contains "-e" and tgt.process.cmdline contains "display" and tgt.process.cmdline contains "dialog" and tgt.process.cmdline contains "answer") and (tgt.process.cmdline contains "admin" or tgt.process.cmdline contains "administrator" or tgt.process.cmdline contains "authenticate" or tgt.process.cmdline contains "authentication" or tgt.process.cmdline contains "credentials" or tgt.process.cmdline contains "pass" or tgt.process.cmdline contains "password" or tgt.process.cmdline contains "unlock")))
```


# Original Sigma Rule:
```yaml
title: GUI Input Capture - macOS
id: 60f1ce20-484e-41bd-85f4-ac4afec2c541
status: test
description: Detects attempts to use system dialog prompts to capture user credentials
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.002/T1056.002.md
    - https://scriptingosx.com/2018/08/user-interaction-from-bash-scripts/
author: remotephone, oscd.community
date: 2020-10-13
modified: 2025-12-05
tags:
    - attack.collection
    - attack.credential-access
    - attack.t1056.002
logsource:
    product: macos
    category: process_creation
detection:
    selection_img:
        Image|endswith: '/osascript'
    selection_cli_1:
        CommandLine|contains|all:
            - '-e'
            - 'display'
            - 'dialog'
            - 'answer'
    selection_cli_2:
        CommandLine|contains:
            - 'admin'
            - 'administrator'
            - 'authenticate'
            - 'authentication'
            - 'credentials'
            - 'pass'
            - 'password'
            - 'unlock'
    condition: all of selection_*
falsepositives:
    - Legitimate administration tools and activities
level: low
```
