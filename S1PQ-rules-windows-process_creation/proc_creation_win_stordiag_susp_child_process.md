```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\stordiag.exe" and (tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\fltmc.exe")) and (not (src.process.image.path contains "c:\\windows\\system32\\" or src.process.image.path contains "c:\\windows\\syswow64\\"))))
```


# Original Sigma Rule:
```yaml
title: Execution via stordiag.exe
id: 961e0abb-1b1e-4c84-a453-aafe56ad0d34
status: test
description: Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe
references:
    - https://strontic.github.io/xcyclopedia/library/stordiag.exe-1F08FC87C373673944F6A7E8B18CD845.html
    - https://twitter.com/eral4m/status/1451112385041911809
author: Austin Songer (@austinsonger)
date: 2021-10-21
modified: 2022-12-25
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\stordiag.exe'
        Image|endswith:
            - '\schtasks.exe'
            - '\systeminfo.exe'
            - '\fltmc.exe'
    filter:
        ParentImage|startswith: # as first is "Copy c:\windows\system32\stordiag.exe to a folder"
            - 'c:\windows\system32\'
            - 'c:\windows\syswow64\'
    condition: selection and not filter
falsepositives:
    - Legitimate usage of stordiag.exe.
level: high
```
