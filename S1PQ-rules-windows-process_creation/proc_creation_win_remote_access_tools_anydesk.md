```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\AnyDesk.exe" or tgt.process.image.path contains "\AnyDeskMSI.exe") or tgt.process.displayName="AnyDesk" or tgt.process.displayName="AnyDesk" or tgt.process.publisher="AnyDesk Software GmbH"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - AnyDesk Execution
id: b52e84a3-029e-4529-b09b-71d19dd27e94
status: test
related:
    - id: 065b00ca-5d5c-4557-ac95-64a6d0b64d86
      type: similar
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-2---anydesk-files-detected-test-on-windows
    - https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
author: frack113
date: 2022-02-11
modified: 2025-02-24
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\AnyDesk.exe'
              - '\AnyDeskMSI.exe'
        - Description: AnyDesk
        - Product: AnyDesk
        - Company: AnyDesk Software GmbH
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
