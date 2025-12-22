```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\cmd.exe" and (src.process.image.path contains "\\csrss.exe" or src.process.image.path contains "\\ctfmon.exe" or src.process.image.path contains "\\dllhost.exe" or src.process.image.path contains "\\epad.exe" or src.process.image.path contains "\\FlashPlayerUpdateService.exe" or src.process.image.path contains "\\GoogleUpdate.exe" or src.process.image.path contains "\\jucheck.exe" or src.process.image.path contains "\\jusched.exe" or src.process.image.path contains "\\LogonUI.exe" or src.process.image.path contains "\\lsass.exe" or src.process.image.path contains "\\regsvr32.exe" or src.process.image.path contains "\\SearchIndexer.exe" or src.process.image.path contains "\\SearchProtocolHost.exe" or src.process.image.path contains "\\SIHClient.exe" or src.process.image.path contains "\\sihost.exe" or src.process.image.path contains "\\slui.exe" or src.process.image.path contains "\\spoolsv.exe" or src.process.image.path contains "\\sppsvc.exe" or src.process.image.path contains "\\taskhostw.exe" or src.process.image.path contains "\\unsecapp.exe" or src.process.image.path contains "\\WerFault.exe" or src.process.image.path contains "\\wermgr.exe" or src.process.image.path contains "\\wlanext.exe" or src.process.image.path contains "\\WUDFHost.exe")))
```


# Original Sigma Rule:
```yaml
title: Unusual Parent Process For Cmd.EXE
id: 4b991083-3d0e-44ce-8fc4-b254025d8d4b
status: test
description: Detects suspicious parent process for cmd.exe
references:
    - https://www.elastic.co/guide/en/security/current/unusual-parent-process-for-cmd.exe.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-21
modified: 2023-12-05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        ParentImage|endswith:
            - '\csrss.exe'
            - '\ctfmon.exe'
            - '\dllhost.exe'
            - '\epad.exe'
            - '\FlashPlayerUpdateService.exe'
            - '\GoogleUpdate.exe'
            - '\jucheck.exe'
            - '\jusched.exe'
            - '\LogonUI.exe'
            - '\lsass.exe'
            - '\regsvr32.exe'
            - '\SearchIndexer.exe'
            - '\SearchProtocolHost.exe'
            - '\SIHClient.exe'
            - '\sihost.exe'
            - '\slui.exe'
            - '\spoolsv.exe'
            - '\sppsvc.exe'
            - '\taskhostw.exe'
            - '\unsecapp.exe'
            - '\WerFault.exe'
            - '\wermgr.exe'
            - '\wlanext.exe'
            - '\WUDFHost.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
