```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.image.path contains "\bash" and (tgt.process.cmdline contains "id -Gn `" or tgt.process.cmdline contains "id -Gn '")))
```


# Original Sigma Rule:
```yaml
title: Apache Spark Shell Command Injection - ProcessCreation
id: c8a5f584-cdc8-42cc-8cce-0398e4265de3
status: test
description: Detects attempts to exploit an apache spark server via CVE-2014-6287 from a commandline perspective
references:
    - https://github.com/W01fh4cker/cve-2022-33891/blob/fd973b56e78bca8822caa3a2e3cf1b5aff5d0950/cve_2022_33891_poc.py
    - https://sumsec.me/2022/CVE-2022-33891%20Apache%20Spark%20shell%20command%20injection.html
    - https://github.com/apache/spark/pull/36315/files
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-20
tags:
    - attack.initial-access
    - attack.t1190
    - cve.2022-33891
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\bash'
        CommandLine|contains:
            - 'id -Gn `'
            - "id -Gn '"
    condition: selection
falsepositives:
    - Unlikely
level: high
```
