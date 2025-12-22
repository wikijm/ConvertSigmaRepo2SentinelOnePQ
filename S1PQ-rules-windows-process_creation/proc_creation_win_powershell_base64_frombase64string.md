```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "OjpGcm9tQmFzZTY0U3RyaW5n" or tgt.process.cmdline contains "o6RnJvbUJhc2U2NFN0cmluZ" or tgt.process.cmdline contains "6OkZyb21CYXNlNjRTdHJpbm" or (tgt.process.cmdline contains "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA" or tgt.process.cmdline contains "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA" or tgt.process.cmdline contains "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw")))
```


# Original Sigma Rule:
```yaml
title: PowerShell Base64 Encoded FromBase64String Cmdlet
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: test
description: Detects usage of a base64 encoded "FromBase64String" cmdlet in a process command line
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2019-08-24
modified: 2023-04-06
tags:
    - attack.defense-evasion
    - attack.t1140
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|base64offset|contains: '::FromBase64String'
        # UTF-16 LE
        - CommandLine|contains:
              - 'OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA'
              - 'oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA'
              - '6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw'
    condition: selection
falsepositives:
    - Unknown
level: high
```
