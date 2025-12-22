```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path contains "\\excel.exe" or src.process.image.path contains "\\mspub.exe" or src.process.image.path contains "\\onenote.exe" or src.process.image.path contains "\\onenoteim.exe" or src.process.image.path contains "\\outlook.exe" or src.process.image.path contains "\\powerpnt.exe" or src.process.image.path contains "\\winword.exe") and module.path contains "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL"))
```


# Original Sigma Rule:
```yaml
title: GAC DLL Loaded Via Office Applications
id: 90217a70-13fc-48e4-b3db-0d836c5824ac
status: test
description: Detects any GAC DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020-02-19
modified: 2023-02-10
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
        ImageLoaded|startswith: 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL'
    condition: selection
falsepositives:
    - Legitimate macro usage. Add the appropriate filter according to your environment
level: high
```
