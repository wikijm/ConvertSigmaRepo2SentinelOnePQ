```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path="/usr/bin/file" and tgt.process.cmdline matches "(.){200,}") or (tgt.process.image.path="/bin/ls" and tgt.process.cmdline contains "-R") or tgt.process.image.path="/usr/bin/find" or tgt.process.image.path="/usr/bin/mdfind" or tgt.process.image.path="/tree"))
```


# Original Sigma Rule:
```yaml
title: File and Directory Discovery - MacOS
id: 089dbdf6-b960-4bcc-90e3-ffc3480c20f6
status: test
description: Detects usage of system utilities to discover files and directories
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2022-11-25
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: macos
detection:
    select_file_with_asterisk:
        Image: '/usr/bin/file'
        CommandLine|re: '(.){200,}' # execution of the 'file */* *>> /tmp/output.txt' will produce huge commandline
    select_recursive_ls:
        Image: '/bin/ls'
        CommandLine|contains: '-R'
    select_find_execution:
        Image: '/usr/bin/find'
    select_mdfind_execution:
        Image: '/usr/bin/mdfind'
    select_tree_execution|endswith:
        Image: '/tree'
    condition: 1 of select*
falsepositives:
    - Legitimate activities
level: informational
```
