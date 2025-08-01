```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\JWrapper-Remote Access\" or tgt.process.image.path contains "\JWrapper-Remote Support\") and tgt.process.image.path contains "\SimpleService.exe"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Simple Help Execution
id: 95e60a2b-4705-444b-b7da-ba0ea81a3ee2
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-23
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\JWrapper-Remote Access\'
            - '\JWrapper-Remote Support\'
        Image|endswith: '\SimpleService.exe'
    condition: selection
falsepositives:
    - Legitimate usage of the tool
level: medium
```
