```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/nc" or tgt.process.image.path contains "/ncat" or tgt.process.image.path contains "/netcat" or tgt.process.image.path contains "/socat") and (not (tgt.process.cmdline contains " --listen " or tgt.process.cmdline contains " -l "))) or (tgt.process.image.path contains "/autorecon" or tgt.process.image.path contains "/hping" or tgt.process.image.path contains "/hping2" or tgt.process.image.path contains "/hping3" or tgt.process.image.path contains "/naabu" or tgt.process.image.path contains "/nmap" or tgt.process.image.path contains "/nping" or tgt.process.image.path contains "/telnet" or tgt.process.image.path contains "/zenmap")))
```


# Original Sigma Rule:
```yaml
title: Linux Network Service Scanning Tools Execution
id: 3e102cd9-a70d-4a7a-9508-403963092f31
status: test
description: Detects execution of network scanning and reconnaisance tools. These tools can be used for the enumeration of local or remote network services for example.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
    - https://github.com/projectdiscovery/naabu
    - https://github.com/Tib3rius/AutoRecon
author: Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure])
date: 2020-10-21
modified: 2024-09-19
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: linux
detection:
    selection_netcat:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
            - '/socat'
    selection_network_scanning_tools:
        Image|endswith:
            - '/autorecon'
            - '/hping'
            - '/hping2'
            - '/hping3'
            - '/naabu'
            - '/nmap'
            - '/nping'
            - '/telnet' # could be wget, curl, ssh, many things. basically everything that is able to do network connection. consider fine tuning
            - '/zenmap'
    filter_main_netcat_listen_flag:
        CommandLine|contains:
            - ' --listen '
            - ' -l '
    condition: (selection_netcat and not filter_main_netcat_listen_flag) or selection_network_scanning_tools
falsepositives:
    - Legitimate administration activities
level: low
```
