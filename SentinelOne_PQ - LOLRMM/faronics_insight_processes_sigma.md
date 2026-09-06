```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\STAHelper.exe" or src.process.image.path contains "\\FIStudentSvc.exe" or src.process.image.path contains "\\FIStudentAgent.exe" or src.process.image.path contains "\\FIStudentUI.exe" or src.process.image.path contains "\\StudentSvc.exe" or src.process.image.path contains "\\InsightInstaller.exe" or src.process.image.path contains "\\InsightInstallerStudent.exe" or src.process.image.path contains "\\InsightInstallerTeacher.exe") or (tgt.process.image.path contains "\\STAHelper.exe" or tgt.process.image.path contains "\\FIStudentSvc.exe" or tgt.process.image.path contains "\\FIStudentAgent.exe" or tgt.process.image.path contains "\\FIStudentUI.exe" or tgt.process.image.path contains "\\StudentSvc.exe" or tgt.process.image.path contains "\\InsightInstaller.exe" or tgt.process.image.path contains "\\InsightInstallerStudent.exe" or tgt.process.image.path contains "\\InsightInstallerTeacher.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Insight RMM Tool Process Activity
id: b482a35a-df16-5fe7-a755-97f072a3d6ff
status: experimental
description: |
    Detects potential processes activity of Faronics Insight RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\STAHelper.exe'
            - '\\FIStudentSvc.exe'
            - '\\FIStudentAgent.exe'
            - '\\FIStudentUI.exe'
            - '\\StudentSvc.exe'
            - '\\InsightInstaller.exe'
            - '\\InsightInstallerStudent.exe'
            - '\\InsightInstallerTeacher.exe'
    selection_image:
        Image|endswith:
            - '\\STAHelper.exe'
            - '\\FIStudentSvc.exe'
            - '\\FIStudentAgent.exe'
            - '\\FIStudentUI.exe'
            - '\\StudentSvc.exe'
            - '\\InsightInstaller.exe'
            - '\\InsightInstallerStudent.exe'
            - '\\InsightInstallerTeacher.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Faronics Insight
level: medium
```
