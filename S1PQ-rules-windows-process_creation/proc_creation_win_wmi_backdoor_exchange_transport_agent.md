```sql
// Translated content (automatically translated on 29-04-2025 01:59:57):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\EdgeTransport.exe" and (not (tgt.process.image.path="C:\Windows\System32\conhost.exe" or (tgt.process.image.path contains "C:\Program Files\Microsoft\Exchange Server\" and tgt.process.image.path contains "\Bin\OleConverter.exe")))))
```


# Original Sigma Rule:
```yaml
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: test
description: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
author: Florian Roth (Nextron Systems)
date: 2019-10-11
modified: 2023-02-08
tags:
    - attack.persistence
    - attack.t1546.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\EdgeTransport.exe'
    filter_conhost:
        Image: 'C:\Windows\System32\conhost.exe'
    filter_oleconverter:  # FP also documented in https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=18
        Image|startswith: 'C:\Program Files\Microsoft\Exchange Server\'
        Image|endswith: '\Bin\OleConverter.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: critical
```
