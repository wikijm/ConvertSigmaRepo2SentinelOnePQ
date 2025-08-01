```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "DllRegisterServer" and (not tgt.process.image.path contains "\rundll32.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Renamed Rundll32 Execution
id: 2569ed8c-1147-498a-9b8c-2ad3656b10ed
related:
    - id: 0ba1da6d-b6ce-4366-828c-18826c9de23e
      type: derived
status: test
description: Detects when 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection
references:
    - https://twitter.com/swisscom_csirt/status/1331634525722521602?s=20
    - https://app.any.run/tasks/f74c5157-8508-4ac6-9805-d63fe7b0d399/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
modified: 2023-02-03
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'DllRegisterServer'
    filter:
        Image|endswith: '\rundll32.exe'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
