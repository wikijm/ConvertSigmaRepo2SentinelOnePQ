```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((src.process.image.path contains "\excel.exe" or src.process.image.path contains "\mspub.exe" or src.process.image.path contains "\onenote.exe" or src.process.image.path contains "\onenoteim.exe" or src.process.image.path contains "\outlook.exe" or src.process.image.path contains "\powerpnt.exe" or src.process.image.path contains "\winword.exe") and module.path contains "\dsparse.dll"))
```


# Original Sigma Rule:
```yaml
title: Active Directory Parsing DLL Loaded Via Office Application
id: a2a3b925-7bb0-433b-b508-db9003263cc4
status: test
description: Detects DSParse DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020-02-19
modified: 2023-03-28
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
        ImageLoaded|contains: '\dsparse.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
