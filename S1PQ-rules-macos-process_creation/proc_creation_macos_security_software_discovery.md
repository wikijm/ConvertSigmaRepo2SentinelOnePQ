```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path="/usr/bin/grep" and ((tgt.process.cmdline contains "nessusd" or tgt.process.cmdline contains "santad" or tgt.process.cmdline contains "CbDefense" or tgt.process.cmdline contains "falcond" or tgt.process.cmdline contains "td-agent" or tgt.process.cmdline contains "packetbeat" or tgt.process.cmdline contains "filebeat" or tgt.process.cmdline contains "auditbeat" or tgt.process.cmdline contains "osqueryd" or tgt.process.cmdline contains "BlockBlock" or tgt.process.cmdline contains "LuLu") or (tgt.process.cmdline contains "Little" and tgt.process.cmdline contains "Snitch"))))
```


# Original Sigma Rule:
```yaml
title: Security Software Discovery - MacOs
id: 0ed75b9c-c73b-424d-9e7d-496cd565fbe0
status: test
description: Detects usage of system utilities (only grep for now) to discover security software discovery
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518.001/T1518.001.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2022-11-27
tags:
    - attack.discovery
    - attack.t1518.001
logsource:
    category: process_creation
    product: macos
detection:
    image:
        Image: '/usr/bin/grep'
    selection_cli_1:
        CommandLine|contains:
            - 'nessusd'        # nessus vulnerability scanner
            - 'santad'         # google santa
            - 'CbDefense'      # carbon black
            - 'falcond'        # crowdstrike falcon
            - 'td-agent'       # fluentd log shipper
            - 'packetbeat'     # elastic network logger/shipper
            - 'filebeat'       # elastic log file shipper
            - 'auditbeat'      # elastic auditing agent/log shipper
            - 'osqueryd'       # facebook osquery
            - 'BlockBlock'     # Objective-See persistence locations watcher/blocker
            - 'LuLu'           # Objective-See firewall management utility
    selection_cli_2: # Objective Development Software firewall management utility
        CommandLine|contains|all:
            - 'Little'
            - 'Snitch'
    condition: image and 1 of selection_cli_*
falsepositives:
    - Legitimate activities
level: medium
```
