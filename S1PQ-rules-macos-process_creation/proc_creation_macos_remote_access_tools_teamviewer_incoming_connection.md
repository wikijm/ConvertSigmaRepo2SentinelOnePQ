```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (src.process.image.path contains "/TeamViewer_Service" and tgt.process.image.path contains "/TeamViewer_Desktop" and tgt.process.cmdline contains "/TeamViewer_Desktop --IPCport 5939 --Module 1"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Team Viewer Session Started On MacOS Host
id: f459ccb4-9805-41ea-b5b2-55e279e2424a
related:
    - id: ab70c354-d9ac-4e11-bbb6-ec8e3b153357
      type: similar
    - id: 1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
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
    - attack.persistence
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|endswith: '/TeamViewer_Service'
        Image|endswith: '/TeamViewer_Desktop'
        CommandLine|endswith: '/TeamViewer_Desktop --IPCport 5939 --Module 1'
    condition: selection
falsepositives:
    - Legitimate usage of TeamViewer
level: low
```
