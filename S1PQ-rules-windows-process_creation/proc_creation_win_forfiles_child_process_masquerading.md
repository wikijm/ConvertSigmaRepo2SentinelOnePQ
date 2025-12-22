```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.cmdline contains ".exe" or src.process.cmdline contains ".exe\"") and tgt.process.image.path contains "\\cmd.exe" and tgt.process.cmdline contains "/c echo \"") and (not ((src.process.image.path contains ":\\Windows\\System32\\" or src.process.image.path contains ":\\Windows\\SysWOW64\\") and src.process.image.path contains "\\forfiles.exe" and (tgt.process.image.path contains ":\\Windows\\System32\\" or tgt.process.image.path contains ":\\Windows\\SysWOW64\\") and tgt.process.image.path contains "\\cmd.exe"))))
```


# Original Sigma Rule:
```yaml
title: Forfiles.EXE Child Process Masquerading
id: f53714ec-5077-420e-ad20-907ff9bb2958
status: test
description: |
    Detects the execution of "forfiles" from a non-default location, in order to potentially spawn a custom "cmd.exe" from the current working directory.
references:
    - https://www.hexacorn.com/blog/2023/12/31/1-little-known-secret-of-forfiles-exe/
author: Nasreddine Bencherchali (Nextron Systems), Anish Bogati
date: 2024-01-05
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Notes:
        #   - The parent must not have CLI options
        #   - The Child Image must be named "cmd" as its hardcoded in the "forfiles" binary
        #   - The Child CLI will always contains "/c echo" as its hardcoded in the original "forfiles" binary
        ParentCommandLine|endswith:
            - '.exe'
            - '.exe"'
        Image|endswith: '\cmd.exe'
        CommandLine|startswith: '/c echo "'
    filter_main_parent_not_sys:
        ParentImage|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
        ParentImage|endswith: '\forfiles.exe'
        Image|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
        Image|endswith: '\cmd.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
