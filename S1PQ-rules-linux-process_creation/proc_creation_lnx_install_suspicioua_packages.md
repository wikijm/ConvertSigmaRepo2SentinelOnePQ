```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((((tgt.process.image.path contains "/apt" or tgt.process.image.path contains "/apt-get") and tgt.process.cmdline contains "install") or (tgt.process.image.path contains "/yum" and (tgt.process.cmdline contains "localinstall" or tgt.process.cmdline contains "install")) or (tgt.process.image.path contains "/rpm" and tgt.process.cmdline contains "-i") or (tgt.process.image.path contains "/dpkg" and (tgt.process.cmdline contains "--install" or tgt.process.cmdline contains "-i"))) and (tgt.process.cmdline contains "nmap" or tgt.process.cmdline contains " nc" or tgt.process.cmdline contains "netcat" or tgt.process.cmdline contains "wireshark" or tgt.process.cmdline contains "tshark" or tgt.process.cmdline contains "openconnect" or tgt.process.cmdline contains "proxychains")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Package Installed - Linux
id: 700fb7e8-2981-401c-8430-be58e189e741
status: test
description: Detects installation of suspicious packages using system installation utilities
references:
    - https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-03
tags:
    - attack.defense-evasion
    - attack.t1553.004
logsource:
    product: linux
    category: process_creation
detection:
    selection_tool_apt:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains: 'install'
    selection_tool_yum:
        Image|endswith: '/yum'
        CommandLine|contains:
            - 'localinstall'
            - 'install'
    selection_tool_rpm:
        Image|endswith: '/rpm'
        CommandLine|contains: '-i'
    selection_tool_dpkg:
        Image|endswith: '/dpkg'
        CommandLine|contains:
            - '--install'
            - '-i'
    selection_keyword:
        CommandLine|contains:
            # Add more suspicious packages
            - 'nmap'
            - ' nc'
            - 'netcat'
            - 'wireshark'
            - 'tshark'
            - 'openconnect'
            - 'proxychains'
    condition: 1 of selection_tool_* and selection_keyword
falsepositives:
    - Legitimate administration activities
level: medium
```
