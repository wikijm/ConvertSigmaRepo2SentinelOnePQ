```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/grep" or tgt.process.image.path contains "/egrep") and (tgt.process.cmdline contains "nessusd" or tgt.process.cmdline contains "td-agent" or tgt.process.cmdline contains "packetbeat" or tgt.process.cmdline contains "filebeat" or tgt.process.cmdline contains "auditbeat" or tgt.process.cmdline contains "osqueryd" or tgt.process.cmdline contains "cbagentd" or tgt.process.cmdline contains "falcond")))
```


# Original Sigma Rule:
```yaml
title: Security Software Discovery - Linux
id: c9d8b7fd-78e4-44fe-88f6-599135d46d60
status: test
description: Detects usage of system utilities (only grep and egrep for now) to discover security software discovery
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
    product: linux
detection:
    selection:
        Image|endswith:
            # You can add more grep variations such as fgrep, rgrep...etc
            - '/grep'
            - '/egrep'
        CommandLine|contains:
            - 'nessusd'        # nessus vulnerability scanner
            - 'td-agent'       # fluentd log shipper
            - 'packetbeat'     # elastic network logger/shipper
            - 'filebeat'       # elastic log file shipper
            - 'auditbeat'      # elastic auditing agent/log shipper
            - 'osqueryd'       # facebook osquery
            - 'cbagentd'       # carbon black
            - 'falcond'        # crowdstrike falcon
    condition: selection
falsepositives:
    - Legitimate activities
level: low
```
