```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\dnscmd.exe" and (tgt.process.cmdline contains "/enumrecords" or tgt.process.cmdline contains "/enumzones" or tgt.process.cmdline contains "/ZonePrint" or tgt.process.cmdline contains "/info")))
```


# Original Sigma Rule:
```yaml
title: Potential Discovery Activity Via Dnscmd.EXE
id: b6457d63-d2a2-4e29-859d-4e7affc153d1
status: test
description: Detects an attempt to leverage dnscmd.exe to enumerate the DNS zones of a domain. DNS zones used to host the DNS records for a particular domain.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd
    - https://learn.microsoft.com/en-us/azure/dns/dns-zones-records
    - https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/
author: '@gott_cyber'
date: 2022-07-31
modified: 2023-02-04
tags:
    - attack.discovery
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\dnscmd.exe'
    selection_cli:
        CommandLine|contains:
            - '/enumrecords'
            - '/enumzones'
            - '/ZonePrint'
            - '/info'
    condition: all of selection_*
falsepositives:
    - Legitimate administration use
level: medium
```
