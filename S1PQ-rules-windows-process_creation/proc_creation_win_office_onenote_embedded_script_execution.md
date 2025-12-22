```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\onenote.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe") and (tgt.process.cmdline contains "\\exported\\" or tgt.process.cmdline contains "\\onenoteofflinecache_files\\")))
```


# Original Sigma Rule:
```yaml
title: OneNote.EXE Execution of Malicious Embedded Scripts
id: 84b1706c-932a-44c4-ae28-892b28a25b94
status: test
description: |
    Detects the execution of malicious OneNote documents that contain embedded scripts.
    When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.
references:
    - https://bazaar.abuse.ch/browse/tag/one/
author: '@kostastsale'
date: 2023-02-02
tags:
    - attack.defense-evasion
    - attack.t1218.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\onenote.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        CommandLine|contains:
            - '\exported\'
            - '\onenoteofflinecache_files\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
