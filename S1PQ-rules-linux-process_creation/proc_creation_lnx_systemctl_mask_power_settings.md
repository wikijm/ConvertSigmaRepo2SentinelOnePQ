```sql
// Translated content (automatically translated on 25-10-2025 00:52:37):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/systemctl" and tgt.process.cmdline contains " mask") and (tgt.process.cmdline contains "suspend.target" or tgt.process.cmdline contains "hibernate.target" or tgt.process.cmdline contains "hybrid-sleep.target")))
```


# Original Sigma Rule:
```yaml
title: Mask System Power Settings Via Systemctl
id: c172b7b5-f3a1-4af2-90b7-822c63df86cb
status: experimental
description: |
    Detects the use of systemctl mask to disable system power management targets such as suspend, hibernate, or hybrid sleep.
    Adversaries may mask these targets to prevent a system from entering sleep or shutdown states, ensuring their malicious processes remain active and uninterrupted.
    This behavior can be associated with persistence or defense evasion, as it impairs normal system power operations to maintain long-term access or avoid termination of malicious activity.
author: Milad Cheraghi, Nasreddine Bencherchali
date: 2025-10-17
references:
    - https://www.man7.org/linux/man-pages/man1/systemctl.1.html
    - https://linux-audit.com/systemd/faq/what-is-the-difference-between-systemctl-disable-and-systemctl-mask/
tags:
    - attack.persistence
    - attack.impact
    - attack.t1653
logsource:
    category: process_creation
    product: linux
detection:
    selection_systemctl:
        Image|endswith: '/systemctl'
        CommandLine|contains: ' mask'
    selection_power_options:
        CommandLine|contains:
            - 'suspend.target'
            - 'hibernate.target'
            - 'hybrid-sleep.target'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
