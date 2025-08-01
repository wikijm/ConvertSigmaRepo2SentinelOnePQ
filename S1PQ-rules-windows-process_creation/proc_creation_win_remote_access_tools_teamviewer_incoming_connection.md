```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path="TeamViewer_Desktop.exe" and src.process.image.path="TeamViewer_Service.exe" and tgt.process.cmdline contains "TeamViewer_Desktop.exe --IPCport 5939 --Module 1"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Team Viewer Session Started On Windows Host
id: ab70c354-d9ac-4e11-bbb6-ec8e3b153357
related:
    - id: 1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
      type: similar
    - id: f459ccb4-9805-41ea-b5b2-55e279e2424a
      type: similar
status: test
description: |
    Detects the command line executed when TeamViewer starts a session started by a remote host.
    Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.
references:
    - Internal Research
author: Josh Nickels, Qi Nan
date: 2024-03-11
tags:
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'TeamViewer_Desktop.exe'
        ParentImage: 'TeamViewer_Service.exe'
        CommandLine|endswith: 'TeamViewer_Desktop.exe --IPCport 5939 --Module 1'
    condition: selection
falsepositives:
    - Legitimate usage of TeamViewer
level: low
```
