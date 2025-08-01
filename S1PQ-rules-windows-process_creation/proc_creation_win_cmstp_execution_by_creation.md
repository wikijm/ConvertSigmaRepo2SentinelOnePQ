```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\cmstp.exe") | columns tgt.process.cmdline,src.process.cmdline,Details
```


# Original Sigma Rule:
```yaml
title: CMSTP Execution Process Creation
id: 7d4cdc5a-0076-40ca-aac8-f7e714570e47
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
author: Nik Seetharaman
date: 2018-07-16
modified: 2020-12-23
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    # CMSTP Spawning Child Process
    selection:
        ParentImage|endswith: '\cmstp.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
```
