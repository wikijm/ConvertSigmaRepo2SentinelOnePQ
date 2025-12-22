```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\svchost.exe" and (tgt.process.image.path contains "\\eqnedt32.exe" or tgt.process.image.path contains "\\excel.exe" or tgt.process.image.path contains "\\msaccess.exe" or tgt.process.image.path contains "\\mspub.exe" or tgt.process.image.path contains "\\powerpnt.exe" or tgt.process.image.path contains "\\visio.exe" or tgt.process.image.path contains "\\winword.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious New Instance Of An Office COM Object
id: 9bdaf1e9-fdef-443b-8081-4341b74a7e28
status: test
description: |
    Detects an svchost process spawning an instance of an office application. This happens when the initial word application creates an instance of one of the Office COM objects such as 'Word.Application', 'Excel.Application', etc.
    This can be used by malicious actors to create malicious Office documents with macros on the fly. (See vba2clr project in the references)
references:
    - https://learn.microsoft.com/en-us/previous-versions/office/troubleshoot/office-developer/automate-word-create-file-using-visual-basic
    - https://github.com/med0x2e/vba2clr
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-13
modified: 2023-12-19
tags:
    - attack.execution
    - attack.defense-evasion
    - detection.threat-hunting
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith:
            - '\eqnedt32.exe'
            - '\excel.exe'
            - '\msaccess.exe'
            - '\mspub.exe'
            - '\powerpnt.exe'
            - '\visio.exe'
            - '\winword.exe'
    condition: selection
falsepositives:
    - Legitimate usage of office automation via scripting
level: medium
```
