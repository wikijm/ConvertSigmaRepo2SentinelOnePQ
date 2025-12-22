```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/sysadminctl" and (tgt.process.cmdline contains " -guestAccount" and tgt.process.cmdline contains " on")))
```


# Original Sigma Rule:
```yaml
title: Guest Account Enabled Via Sysadminctl
id: d7329412-13bd-44ba-a072-3387f804a106
status: test
description: Detects attempts to enable the guest account using the sysadminctl utility
references:
    - https://ss64.com/osx/sysadminctl.html
author: Sohan G (D4rkCiph3r)
date: 2023-02-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.defense-evasion
    - attack.initial-access
    - attack.t1078
    - attack.t1078.001
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/sysadminctl'
        CommandLine|contains|all:
            # By default the guest account is not active
            - ' -guestAccount'
            - ' on'
    condition: selection
falsepositives:
    - Unknown
level: low
```
