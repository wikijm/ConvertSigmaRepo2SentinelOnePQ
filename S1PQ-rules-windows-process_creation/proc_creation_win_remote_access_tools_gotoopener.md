```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName="GoTo Opener" or tgt.process.displayName="GoTo Opener" or tgt.process.publisher="LogMeIn, Inc."))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - GoToAssist Execution
id: b6d98a4f-cef0-4abf-bbf6-24132854a83d
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
author: frack113
date: 2022-02-13
modified: 2023-03-05
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: 'GoTo Opener'
        - Product: 'GoTo Opener'
        - Company: 'LogMeIn, Inc.'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
