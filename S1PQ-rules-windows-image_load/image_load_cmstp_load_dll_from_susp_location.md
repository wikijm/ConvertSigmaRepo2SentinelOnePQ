```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\cmstp.exe" and (module.path contains "\\PerfLogs\\" or module.path contains "\\ProgramData\\" or module.path contains "\\Users\\" or module.path contains "\\Windows\\Temp\\" or module.path contains "C:\\Temp\\") and (module.path contains ".dll" or module.path contains ".ocx")))
```


# Original Sigma Rule:
```yaml
title: DLL Loaded From Suspicious Location Via Cmspt.EXE
id: 75e508f7-932d-4ebc-af77-269237a84ce1
status: test
description: Detects cmstp loading "dll" or "ocx" files from suspicious locations
references:
    - https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/02bcbfc2bfb8b4da601bb30de0344ae453aa1afe/TTPs/Defense%20Evasion/T1218%20-%20Signed%20Binary%20Proxy%20Execution/T1218.003%20-%20CMSTP/Procedures.yaml
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-30
modified: 2023-02-17
tags:
    - attack.defense-evasion
    - attack.t1218.003
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\cmstp.exe'
        ImageLoaded|contains:
            # Add more suspicious paths as you see fit in your env
            - '\PerfLogs\'
            - '\ProgramData\'
            - '\Users\'
            - '\Windows\Temp\'
            - 'C:\Temp\'
        ImageLoaded|endswith:
            - '.dll'
            - '.ocx'
    condition: selection
falsepositives:
    - Unikely
level: high
```
