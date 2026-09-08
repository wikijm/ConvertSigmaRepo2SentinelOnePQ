```sql
// Translated content (automatically translated on 08-09-2026 02:04:58):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/service" or tgt.process.image.path contains "/systemctl" or tgt.process.image.path contains "/chkconfig") and (tgt.process.cmdline contains " stop " or tgt.process.cmdline contains " disable ")) and (not ((tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "--no-reload disable snap-snapd-" or tgt.process.cmdline contains " stop snap-snapd-")) or (tgt.process.image.path contains "/systemctl" and src.process.cmdline contains "tmp.ci/preinst upgrade" and (tgt.process.cmdline contains " stop " and tgt.process.cmdline contains "ssh.")) or (src.process.cmdline contains "/dpkg/info/ubuntu-pro-client.prerm upgrade" and tgt.process.image.path contains "/systemctl"))) and (not (tgt.process.image.path contains "/systemctl" and tgt.process.cmdline contains "snap.amazon-ssm-agent.amazon-ssm-agent.service"))))
```


# Original Sigma Rule:
```yaml
title: Disable Or Stop Services
id: de25eeb8-3655-4643-ac3a-b662d3f26b6b
status: test
description: |
    Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services on Linux systems.
    Attackers may stop or disable security tools and services to evade detection, maintain persistence, or disrupt system operations.
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
modified: 2025-03-18
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/service'
            - '/systemctl'
            - '/chkconfig'
        CommandLine|contains:
            - ' stop '
            - ' disable '
    filter_main_legit_snapd:
        Image|endswith: '/systemctl'
        CommandLine|contains:
            - '--no-reload disable snap-snapd-'
            - ' stop snap-snapd-'
    filter_main_ssh_preinstall:
        Image|endswith: '/systemctl'
        ParentCommandLine|contains: 'tmp.ci/preinst upgrade'
        CommandLine|contains|all:
            - ' stop '
            - 'ssh.'
    filter_main_ubuntu_upgrade:
        ParentCommandLine|contains: '/dpkg/info/ubuntu-pro-client.prerm upgrade'
        Image|endswith: '/systemctl'
    filter_optional_aws_agent:
        Image|endswith: '/systemctl'
        CommandLine|endswith: 'snap.amazon-ssm-agent.amazon-ssm-agent.service'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate administration activities
    - Some false positives are to be expected. Apply additional filters as needed before pushing to production.
level: medium
```
