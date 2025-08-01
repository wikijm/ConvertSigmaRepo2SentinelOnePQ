```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/service" and (tgt.process.cmdline contains "iptables" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/service" and (tgt.process.cmdline contains "ip6tables" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/chkconfig" and (tgt.process.cmdline contains "iptables" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/chkconfig" and (tgt.process.cmdline contains "ip6tables" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "firewalld" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "firewalld" and tgt.process.cmdline contains "disable")) or (tgt.process.image.path contains "/service" and (tgt.process.cmdline contains "cbdaemon" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/chkconfig" and (tgt.process.cmdline contains "cbdaemon" and tgt.process.cmdline contains "off")) or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "cbdaemon" and tgt.process.cmdline contains "stop")) or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "cbdaemon" and tgt.process.cmdline contains "disable")) or (tgt.process.image.path contains "/setenforce" and tgt.process.cmdline contains "0") or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "stop" and tgt.process.cmdline contains "falcon-sensor")) or (tgt.process.image.path contains "/systemctl" and (tgt.process.cmdline contains "disable" and tgt.process.cmdline contains "falcon-sensor"))))
```


# Original Sigma Rule:
```yaml
title: Disabling Security Tools
id: e3a8a052-111f-4606-9aee-f28ebeb76776
status: test
description: Detects disabling security tools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-06-17
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1562.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_iptables_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'iptables'
            - 'stop'
    selection_iptables_2:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'ip6tables'
            - 'stop'
    selection_iptables_3:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'iptables'
            - 'stop'
    selection_iptables_4:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'ip6tables'
            - 'stop'
    selection_firewall_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'firewalld'
            - 'stop'
    selection_firewall_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'firewalld'
            - 'disable'
    selection_carbonblack_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'stop'
    selection_carbonblack_2:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'off'
    selection_carbonblack_3:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'stop'
    selection_carbonblack_4:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'disable'
    selection_selinux:
        Image|endswith: '/setenforce'
        CommandLine|contains: '0'
    selection_crowdstrike_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'stop'
            - 'falcon-sensor'
    selection_crowdstrike_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'disable'
            - 'falcon-sensor'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```
