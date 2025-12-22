```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\msdt.exe" and module.path contains "\\sdiageng.dll"))
```


# Original Sigma Rule:
```yaml
title: Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE
id: ec8c4047-fad9-416a-8c81-0f479353d7f6
status: test
description: Detects both of CVE-2022-30190 (Follina) and DogWalk vulnerabilities exploiting msdt.exe binary to load the "sdiageng.dll" library
references:
    - https://www.securonix.com/blog/detecting-microsoft-msdt-dogwalk/
author: Greg (rule)
date: 2022-06-17
modified: 2023-02-17
tags:
    - attack.defense-evasion
    - attack.t1202
    - cve.2022-30190
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\msdt.exe'
        ImageLoaded|endswith: '\sdiageng.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
