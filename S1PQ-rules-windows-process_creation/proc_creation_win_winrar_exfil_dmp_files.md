```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\rar.exe" or tgt.process.image.path contains "\\winrar.exe") or tgt.process.displayName="Command line RAR") and (tgt.process.cmdline contains ".dmp" or tgt.process.cmdline contains ".dump" or tgt.process.cmdline contains ".hdmp")))
```


# Original Sigma Rule:
```yaml
title: Winrar Compressing Dump Files
id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
related:
    - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
      type: similar
status: test
description: Detects execution of WinRAR in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
references:
    - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
author: Florian Roth (Nextron Systems)
date: 2022-01-04
modified: 2023-09-12
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\rar.exe'
              - '\winrar.exe'
        - Description: 'Command line RAR'
    selection_extension:
        CommandLine|contains:
            - '.dmp'
            - '.dump'
            - '.hdmp'
    condition: all of selection_*
falsepositives:
    - Legitimate use of WinRAR with a command line in which ".dmp" or ".dump" appears accidentally
    - Legitimate use of WinRAR to compress WER ".dmp" files for troubleshooting
level: medium
```
