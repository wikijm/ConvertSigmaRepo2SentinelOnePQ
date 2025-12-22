```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/yum" and (tgt.process.cmdline contains "erase" or tgt.process.cmdline contains "remove")) or ((tgt.process.image.path contains "/apt" or tgt.process.image.path contains "/apt-get") and (tgt.process.cmdline contains "remove" or tgt.process.cmdline contains "purge")) or (tgt.process.image.path contains "/dpkg" and (tgt.process.cmdline contains "--remove " or tgt.process.cmdline contains " -r ")) or (tgt.process.image.path contains "/rpm" and tgt.process.cmdline contains " -e ")))
```


# Original Sigma Rule:
```yaml
title: Linux Package Uninstall
id: 95d61234-7f56-465c-6f2d-b562c6fedbc4
status: test
description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
references:
    - https://sysdig.com/blog/mitre-defense-evasion-falco
    - https://www.tutorialspoint.com/how-to-install-a-software-on-linux-using-yum-command
    - https://linuxhint.com/uninstall_yum_package/
    - https://linuxhint.com/uninstall-debian-packages/
author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-09
tags:
    - attack.defense-evasion
    - attack.t1070
logsource:
    product: linux
    category: process_creation
detection:
    selection_yum:
        Image|endswith: '/yum'
        CommandLine|contains:
            - 'erase'
            - 'remove'
    selection_apt:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains:
            - 'remove'
            - 'purge'
    selection_dpkg:
        Image|endswith: '/dpkg'
        CommandLine|contains:
            - '--remove '
            - ' -r '
    selection_rpm:
        Image|endswith: '/rpm'
        CommandLine|contains: ' -e '
    condition: 1 of selection_*
falsepositives:
    - Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting).
level: low
```
