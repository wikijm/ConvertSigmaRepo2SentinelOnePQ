```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path in ("/bin/dd","/usr/bin/dd")) and tgt.process.cmdline contains "of=" and (tgt.process.cmdline contains "if=/dev/zero" or tgt.process.cmdline contains "if=/dev/null")))
```


# Original Sigma Rule:
```yaml
title: DD File Overwrite
id: 2953194b-e33c-4859-b9e8-05948c167447
status: test
description: Detects potential overwriting and deletion of a file using DD.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2022-07-07
tags:
    - attack.impact
    - attack.t1485
logsource:
    product: linux
    category: process_creation
detection:
    selection1:
        Image:
            - '/bin/dd'
            - '/usr/bin/dd'
    selection2:
        CommandLine|contains: 'of='
    selection3:
        CommandLine|contains:
            - 'if=/dev/zero'
            - 'if=/dev/null'
    condition: all of selection*
falsepositives:
    - Any user deleting files that way.
level: low
```
