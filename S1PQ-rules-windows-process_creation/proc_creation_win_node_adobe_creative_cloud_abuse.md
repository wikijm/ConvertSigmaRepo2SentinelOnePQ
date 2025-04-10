```sql
// Translated content (automatically translated on 10-04-2025 01:55:35):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\Adobe Creative Cloud Experience\libs\node.exe" and (not tgt.process.cmdline contains "Adobe Creative Cloud Experience\js"))) | columns tgt.process.image.path,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Node Process Executions
id: df1f26d3-bea7-4700-9ea2-ad3e990cf90e
status: test
description: Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud
references:
    - https://twitter.com/mttaggart/status/1511804863293784064
author: Max Altgelt (Nextron Systems)
date: 2022-04-06
tags:
    - attack.defense-evasion
    - attack.t1127
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Adobe Creative Cloud Experience\libs\node.exe'
    filter:
        CommandLine|contains: 'Adobe Creative Cloud Experience\js' # Folder where Creative Cloud's JS resources are located
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium
```
