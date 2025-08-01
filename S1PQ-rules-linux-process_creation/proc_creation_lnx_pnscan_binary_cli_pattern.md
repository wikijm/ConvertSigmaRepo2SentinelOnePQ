```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.cmdline matches "-(W|R)\\s?(\\s|"|')([0-9a-fA-F]{2}\\s?){2,20}(\\s|"|')")
```


# Original Sigma Rule:
```yaml
title: Pnscan Binary Data Transmission Activity
id: 97de11cd-4b67-4abf-9a8b-1020e670aa9e
status: test
description: |
    Detects command line patterns associated with the use of Pnscan for sending and receiving binary data across the network.
    This behavior has been identified in a Linux malware campaign targeting Docker, Apache Hadoop, Redis, and Confluence and was previously used by the threat actor known as TeamTNT
author: David Burkett (@signalblur)
date: 2024-04-16
references:
    - https://www.cadosecurity.com/blog/spinning-yarn-a-new-linux-malware-campaign-targets-docker-apache-hadoop-redis-and-confluence
    - https://intezer.com/wp-content/uploads/2021/09/TeamTNT-Cryptomining-Explosion.pdf
    - https://regex101.com/r/RugQYK/1
    - https://www.virustotal.com/gui/file/beddf70a7bab805f0c0b69ac0989db6755949f9f68525c08cb874988353f78a9/content
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|re: -(W|R)\s?(\s|"|')([0-9a-fA-F]{2}\s?){2,20}(\s|"|')
    condition: selection
falsepositives:
    - Unknown
level: medium
```
