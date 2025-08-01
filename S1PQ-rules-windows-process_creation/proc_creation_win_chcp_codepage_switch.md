```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\chcp.com" and (tgt.process.cmdline contains " 936" or tgt.process.cmdline contains " 1258"))) | columns src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious CodePage Switch Via CHCP
id: c7942406-33dd-4377-a564-0f62db0593a3
status: test
description: Detects a code page switch in command line or batch scripts to a rare language
references:
    - https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    - https://twitter.com/cglyer/status/1183756892952248325
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
date: 2019-10-14
modified: 2023-03-07
tags:
    - attack.t1036
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\chcp.com'
        CommandLine|endswith:
            - ' 936'    # Chinese
            # - ' 1256' # Arabic
            - ' 1258'   # Vietnamese
            # - ' 855'  # Russian
            # - ' 866'  # Russian
            # - ' 864'  # Arabic
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Administrative activity (adjust code pages according to your organization's region)
level: medium
```
