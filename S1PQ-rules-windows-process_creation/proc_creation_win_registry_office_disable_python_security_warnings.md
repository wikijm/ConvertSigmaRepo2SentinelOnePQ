```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\Microsoft\Office\" and tgt.process.cmdline contains "\Excel\Security" and tgt.process.cmdline contains "PythonFunctionWarnings") and tgt.process.cmdline contains " 0"))
```


# Original Sigma Rule:
```yaml
title: Python Function Execution Security Warning Disabled In Excel
id: 023c654f-8f16-44d9-bb2b-00ff36a62af9
related:
    - id: 17e53739-a1fc-4a62-b1b9-87711c2d5e44
      type: similar
status: test
description: |
    Detects changes to the registry value "PythonFunctionWarnings" that would prevent any warnings or alerts from showing when Python functions are about to be executed.
    Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet.
references:
    - https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327
author: '@Kostastsale'
date: 2023-08-22
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Microsoft\Office\'
            - '\Excel\Security'
            - 'PythonFunctionWarnings'
        CommandLine|contains: ' 0'
    condition: selection
falsepositives:
    - Unknown
level: high
```
