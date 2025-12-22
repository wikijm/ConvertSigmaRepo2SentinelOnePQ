```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/file" and tgt.process.cmdline matches "(.){200,}") or (tgt.process.image.path contains "/ls" and tgt.process.cmdline contains "-R") or tgt.process.image.path contains "/find" or tgt.process.image.path contains "/tree" or tgt.process.image.path contains "/findmnt" or tgt.process.image.path contains "/mlocate"))
```


# Original Sigma Rule:
```yaml
title: File and Directory Discovery - Linux
id: d3feb4ee-ff1d-4d3d-bd10-5b28a238cc72
status: test
description: |
    Detects usage of system utilities such as "find", "tree", "findmnt", etc, to discover files, directories and network shares.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md
author: Daniil Yugoslavskiy, oscd.community, CheraghiMilad
date: 2020-10-19
modified: 2024-12-01
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_file_with_asterisk:
        Image|endswith: '/file'
        CommandLine|re: '(.){200,}' # execution of the 'file */* *>> /tmp/output.txt' will produce huge commandline
    selection_recursive_ls:
        Image|endswith: '/ls'
        CommandLine|contains: '-R'
    selection_find_execution:
        Image|endswith: '/find'
    selection_tree_execution:
        Image|endswith: '/tree'
    selection_findmnt_execution:
        Image|endswith: '/findmnt'
    selection_locate_execution:
        Image|endswith: '/mlocate'
    condition: 1 of selection_*
falsepositives:
    - Legitimate activities
level: informational
```
