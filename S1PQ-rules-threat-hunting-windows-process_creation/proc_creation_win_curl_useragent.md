```sql
// Translated content (automatically translated on 16-10-2025 00:45:58):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\curl.exe" or tgt.process.displayName="The curl executable") and (tgt.process.cmdline contains " -A " or tgt.process.cmdline contains " --user-agent "))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Curl.EXE Execution With Custom UserAgent
id: 3286d37a-00fd-41c2-a624-a672dcd34e60
status: test
description: Detects execution of curl.exe with custom useragent options
references:
    - https://curl.se/docs/manpage.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1071.001/T1071.001.md#atomic-test-2---malicious-user-agents---cmd
author: frack113
date: 2022-01-23
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1071.001
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        - Image|endswith: '\curl.exe'
        - Product: 'The curl executable'
    selection_opt:
        CommandLine|contains:
            - ' -A '
            - ' --user-agent '
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: medium
```
