```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="C:\Windows\SysWOW64\setup16.exe" and src.process.cmdline contains " -m ") and (not tgt.process.image.path contains "C:\~MSSETUP.T\")))
```


# Original Sigma Rule:
```yaml
title: Setup16.EXE Execution With Custom .Lst File
id: 99c8be4f-3087-4f9f-9c24-8c7e257b442e
status: experimental
description: |
    Detects the execution of "Setup16.EXE" and old installation utility with a custom ".lst" file.
    These ".lst" file can contain references to external program that "Setup16.EXE" will execute.
    Attackers and adversaries might leverage this as a living of the land utility.
references:
    - https://www.hexacorn.com/blog/2024/10/12/the-sweet16-the-oldbin-lolbin-called-setup16-exe/
author: frack113
date: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: 'C:\Windows\SysWOW64\setup16.exe'
        ParentCommandLine|contains: ' -m '
    filter_optional_valid_path:
        Image|startswith: 'C:\~MSSETUP.T\'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - On modern Windows system, the "Setup16" utility is practically never used, hence false positive should be very rare.
level: medium
```
