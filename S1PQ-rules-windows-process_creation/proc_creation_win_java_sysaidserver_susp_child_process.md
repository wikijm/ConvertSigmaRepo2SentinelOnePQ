```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and src.process.cmdline contains "SysAidServer"))
```


# Original Sigma Rule:
```yaml
title: Suspicious SysAidServer Child
id: 60bfeac3-0d35-4302-8efb-1dd16f715bc6
status: test
description: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
references:
    - https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
author: Florian Roth (Nextron Systems)
date: 2022-08-26
tags:
    - attack.lateral-movement
    - attack.t1210
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
        ParentCommandLine|contains: 'SysAidServer'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
