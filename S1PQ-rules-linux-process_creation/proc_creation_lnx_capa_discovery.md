```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/getcap" and (tgt.process.cmdline contains " -r " or tgt.process.cmdline contains " /r " or tgt.process.cmdline contains " –r " or tgt.process.cmdline contains " —r " or tgt.process.cmdline contains " ―r ")))
```


# Original Sigma Rule:
```yaml
title: Capabilities Discovery - Linux
id: d8d97d51-122d-4cdd-9e2f-01b4b4933530
status: test
description: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
references:
    - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
    - https://github.com/carlospolop/PEASS-ng
    - https://github.com/diego-treitos/linux-smart-enumeration
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
modified: 2024-03-05
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/getcap'
        CommandLine|contains|windash: ' -r '
    condition: selection
falsepositives:
    - Unknown
level: low
```
