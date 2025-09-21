```sql
// Translated content (automatically translated on 21-09-2025 02:02:30):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\sysprep.exe" and tgt.process.cmdline contains "\\AppData\\"))
```


# Original Sigma Rule:
```yaml
title: Sysprep on AppData Folder
id: d5b9ae7a-e6fc-405e-80ff-2ff9dcc64e7e
status: test
description: Detects suspicious sysprep process start with AppData folder as target (as used by Trojan Syndicasec in Thrip report by Symantec)
references:
    - https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
    - https://app.any.run/tasks/61a296bb-81ad-4fee-955f-3b399f4aaf4b
author: Florian Roth (Nextron Systems)
date: 2018-06-22
modified: 2021-11-27
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sysprep.exe'
        CommandLine|contains: '\AppData\'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
