```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/iptables" or tgt.process.image.path contains "/xtables-legacy-multi" or tgt.process.image.path contains "/iptables-legacy-multi" or tgt.process.image.path contains "/ip6tables" or tgt.process.image.path contains "/ip6tables-legacy-multi") and (tgt.process.cmdline contains "-F" or tgt.process.cmdline contains "-Z" or tgt.process.cmdline contains "-X") and (tgt.process.cmdline contains "ufw-logging-deny" or tgt.process.cmdline contains "ufw-logging-allow" or tgt.process.cmdline contains "ufw6-logging-deny" or tgt.process.cmdline contains "ufw6-logging-allow")))
```


# Original Sigma Rule:
```yaml
title: Flush Iptables Ufw Chain
id: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
status: test
description: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
references:
    - https://blogs.blackberry.com/
    - https://www.cyberciti.biz/tips/linux-iptables-how-to-flush-all-rules.html
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-18
tags:
    - attack.defense-evasion
    - attack.t1562.004
logsource:
    product: linux
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '/iptables'
            - '/xtables-legacy-multi'
            - '/iptables-legacy-multi'
            - '/ip6tables'
            - '/ip6tables-legacy-multi'
    selection_params:
        CommandLine|contains:
            - '-F'
            - '-Z'
            - '-X'
    selection_ufw:
        CommandLine|contains:
            - 'ufw-logging-deny'
            - 'ufw-logging-allow'
            - 'ufw6-logging-deny'
            - 'ufw6-logging-allow'
            # - 'ufw-reject-output'
            # - 'ufw-track-inputt'
    condition: all of selection_*
falsepositives:
    - Network administrators
level: medium
```
