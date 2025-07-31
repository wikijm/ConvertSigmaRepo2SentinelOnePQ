```sql
// Translated content (automatically translated on 31-07-2025 02:23:44):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName contains "Mouse Lock" or tgt.process.publisher contains "Misc314" or tgt.process.cmdline contains "Mouse Lock_")) | columns tgt.process.displayName,tgt.process.publisher,tgt.process.cmdline
```


# Original Sigma Rule:
```yaml
title: PUA - Mouse Lock Execution
id: c9192ad9-75e5-43eb-8647-82a0a5b493e3
status: test
description: In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.
references:
    - https://github.com/klsecservices/Publications/blob/657deb6a6eb6e00669afd40173f425fb49682eaa/Incident-Response-Analyst-Report-2020.pdf
    - https://sourceforge.net/projects/mouselock/
author: Cian Heasley
date: 2020-08-13
modified: 2023-02-21
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1056.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Product|contains: 'Mouse Lock'
        - Company|contains: 'Misc314'
        - CommandLine|contains: 'Mouse Lock_'
    condition: selection
fields:
    - Product
    - Company
    - CommandLine
falsepositives:
    - Legitimate uses of Mouse Lock software
level: medium
```
