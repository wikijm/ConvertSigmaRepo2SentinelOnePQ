```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\excel.exe" or src.process.image.path contains "\\mspub.exe" or src.process.image.path contains "\\onenote.exe" or src.process.image.path contains "\\onenoteim.exe" or src.process.image.path contains "\\outlook.exe" or src.process.image.path contains "\\powerpnt.exe" or src.process.image.path contains "\\winword.exe") and module.path contains "C:\\Windows\\assembly\\"))
```


# Original Sigma Rule:
```yaml
title: DotNET Assembly DLL Loaded Via Office Application
id: ff0f2b05-09db-4095-b96d-1b75ca24894a
status: test
description: Detects any assembly DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020-02-19
modified: 2023-03-29
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\excel.exe'
            - '\mspub.exe'
            - '\onenote.exe'
            - '\onenoteim.exe' # Just in case
            - '\outlook.exe'
            - '\powerpnt.exe'
            - '\winword.exe'
        ImageLoaded|startswith: 'C:\Windows\assembly\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
