```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\svchost.exe" or tgt.process.image.path contains "\\taskhost.exe" or tgt.process.image.path contains "\\lsm.exe" or tgt.process.image.path contains "\\lsass.exe" or tgt.process.image.path contains "\\services.exe" or tgt.process.image.path contains "\\lsaiso.exe" or tgt.process.image.path contains "\\csrss.exe" or tgt.process.image.path contains "\\wininit.exe" or tgt.process.image.path contains "\\winlogon.exe") and (not (((src.process.image.path contains "\\SavService.exe" or src.process.image.path contains "\\ngen.exe") or (src.process.image.path contains "\\System32\\" or src.process.image.path contains "\\SysWOW64\\")) or ((src.process.image.path contains "\\Windows Defender\\" or src.process.image.path contains "\\Microsoft Security Client\\") and src.process.image.path contains "\\MsMpEng.exe") or (not (src.process.image.path matches "\.*") or (src.process.image.path in ("","-")))))))
```


# Original Sigma Rule:
```yaml
title: Windows Processes Suspicious Parent Directory
id: 96036718-71cc-4027-a538-d1587e0006a7
status: test
description: Detect suspicious parent processes of well-known Windows processes
references:
    - https://web.archive.org/web/20180718061628/https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
    - https://www.carbonblack.com/2014/06/10/screenshot-demo-hunt-evil-faster-than-ever-with-carbon-black/
    - https://www.13cubed.com/downloads/windows_process_genealogy_v2.pdf
author: vburov
date: 2019-02-23
modified: 2025-03-06
tags:
    - attack.defense-evasion
    - attack.t1036.003
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\svchost.exe'
            - '\taskhost.exe'
            - '\lsm.exe'
            - '\lsass.exe'
            - '\services.exe'
            - '\lsaiso.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\winlogon.exe'
    filter_sys:
        - ParentImage|endswith:
              - '\SavService.exe'
              - '\ngen.exe'
        - ParentImage|contains:
              - '\System32\'
              - '\SysWOW64\'
    filter_msmpeng:
        ParentImage|contains:
            - '\Windows Defender\'
            - '\Microsoft Security Client\'
        ParentImage|endswith: '\MsMpEng.exe'
    filter_null:
        - ParentImage: null
        - ParentImage:
              - ''
              - '-'
    condition: selection and not 1 of filter_*
falsepositives:
    - Some security products seem to spawn these
level: low
```
