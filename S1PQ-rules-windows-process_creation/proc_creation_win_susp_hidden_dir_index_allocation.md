```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "::$index_allocation")
```


# Original Sigma Rule:
```yaml
title: Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream - CLI
id: 0900463c-b33b-49a8-be1d-552a3b553dae
related:
    - id: a8f866e1-bdd4-425e-a27a-37619238d9c7
      type: similar
status: test
description: |
    Detects command line containing reference to the "::$index_allocation" stream, which can be used as a technique to prevent access to folders or files from tooling such as "explorer.exe" or "powershell.exe"
references:
    - https://twitter.com/pfiatde/status/1681977680688738305
    - https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
    - https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/
    - https://github.com/redcanaryco/atomic-red-team/blob/5c3b23002d2bbede3c07e7307165fc2a235a427d/atomics/T1564.004/T1564.004.md#atomic-test-5---create-hidden-directory-via-index_allocation
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3
author: Nasreddine Bencherchali (Nextron Systems), Scoubi (@ScoubiMtl)
date: 2023-10-09
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        # Note: Both Sysmon and ETW are unable to log the presence of such stream in the CommandLine. But EDRs such as Crowdstrike are able to using for example CMD console history. Users are advised to test this before usage
        CommandLine|contains: '::$index_allocation'
    condition: selection
falsepositives:
    - Unlikely
level: medium
```
