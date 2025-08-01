```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\outlook.exe" and tgt.process.image.path contains "\\"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Remote Child Process From Outlook
id: e212d415-0e93-435f-9e1a-f29005bb4723
related:
    - id: 208748f7-881d-47ac-a29c-07ea84bf691d # Outlook Child Processes
      type: similar
status: test
description: Detects a suspicious child process spawning from Outlook where the image is located in a remote location (SMB/WebDav shares).
references:
    - https://github.com/sensepost/ruler
    - https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=49
author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
date: 2018-12-27
modified: 2023-02-09
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\outlook.exe'
        Image|startswith: '\\\\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
