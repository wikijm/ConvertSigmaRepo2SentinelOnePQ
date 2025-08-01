```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "X509Enrollment.CBinaryConverter" or tgt.process.cmdline contains "884e2002-217d-11da-b2a4-000e7bbb2b09"))
```


# Original Sigma Rule:
```yaml
title: Suspicious X509Enrollment - Process Creation
id: 114de787-4eb2-48cc-abdb-c0b449f93ea4
related:
    - id: 504d63cb-0dba-4d02-8531-e72981aace2c
      type: similar
status: test
description: Detect use of X509Enrollment
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=42
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=41
    - https://learn.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.cx509enrollmentwebclassfactoryclass?view=hpc-sdk-5.1.6115
author: frack113
date: 2022-12-23
tags:
    - attack.defense-evasion
    - attack.t1553.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'X509Enrollment.CBinaryConverter'
            - '884e2002-217d-11da-b2a4-000e7bbb2b09'
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium
```
