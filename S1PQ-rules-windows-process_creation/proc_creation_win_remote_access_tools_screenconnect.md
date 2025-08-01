```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName="ScreenConnect Service" or tgt.process.displayName="ScreenConnect" or tgt.process.publisher="ScreenConnect Software"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - ScreenConnect Execution
id: 57bff678-25d1-4d6c-8211-8ca106d12053
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-5---screenconnect-application-download-and-install-on-windows
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
        - Description: 'ScreenConnect Service'
        - Product: 'ScreenConnect'
        - Company: 'ScreenConnect Software'
    condition: selection
falsepositives:
    - Legitimate usage of the tool
level: medium
```
