```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\ntvdm.exe" or tgt.process.image.path contains "\csrstub.exe"))
```


# Original Sigma Rule:
```yaml
title: Start of NT Virtual DOS Machine
id: 16905e21-66ee-42fe-b256-1318ada2d770
status: test
description: Ntvdm.exe allows the execution of 16-bit Windows applications on 32-bit Windows operating systems, as well as the execution of both 16-bit and 32-bit DOS applications
references:
    - https://learn.microsoft.com/en-us/windows/compatibility/ntvdm-and-16-bit-app-support
    - https://support.microsoft.com/fr-fr/topic/an-ms-dos-based-program-that-uses-the-ms-dos-protected-mode-interface-crashes-on-a-computer-that-is-running-windows-7-5dc739ea-987b-b458-15e4-d28d5cca63c7
    - https://app.any.run/tasks/93fe92fa-8b2b-4d92-8c09-a841aed2e793/
    - https://app.any.run/tasks/214094a7-0abc-4a7b-a564-1b757faed79d/
author: frack113
date: 2022-07-16
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\ntvdm.exe'
            - '\csrstub.exe'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
