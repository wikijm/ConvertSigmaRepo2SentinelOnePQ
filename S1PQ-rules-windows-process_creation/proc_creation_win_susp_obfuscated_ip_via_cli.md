```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\ping.exe" or tgt.process.image.path contains "\\arp.exe") and ((tgt.process.cmdline contains " 0x" or tgt.process.cmdline contains "//0x" or tgt.process.cmdline contains ".0x" or tgt.process.cmdline contains ".00x") or (tgt.process.cmdline contains "http://%" and tgt.process.cmdline contains "%2e") or (tgt.process.cmdline matches "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}" or tgt.process.cmdline matches "https?://[0-9]{1,3}\\.0[0-9]{3,7}" or tgt.process.cmdline matches "https?://0[0-9]{3,11}" or tgt.process.cmdline matches "https?://(0[0-9]{1,11}\\.){3}0[0-9]{1,11}" or tgt.process.cmdline matches "https?://0[0-9]{1,11}" or tgt.process.cmdline matches " [0-7]{7,13}")) and (not tgt.process.cmdline matches "https?://((25[0-5]|(2[0-4]|1\\d|[1-9])?\\d)(\\.|\\b)){4}")))
```


# Original Sigma Rule:
```yaml
title: Obfuscated IP Via CLI
id: 56d19cb4-6414-4769-9644-1ed35ffbb148
status: test
description: Detects usage of an encoded/obfuscated version of an IP address (hex, octal, etc.) via command line
references:
    - https://h.43z.one/ipconverter/
    - https://twitter.com/Yasser_Elsnbary/status/1553804135354564608
author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
date: 2022-08-03
modified: 2023-11-06
tags:
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\ping.exe'
            - '\arp.exe'
    selection_ip_1:
        CommandLine|contains:
            - ' 0x'
            - '//0x'
            - '.0x'
            - '.00x'
    selection_ip_2:
        CommandLine|contains|all:
            - 'http://%'
            - '%2e'
    selection_ip_3:
        # http://81.4.31754
        - CommandLine|re: 'https?://[0-9]{1,3}\.[0-9]{1,3}\.0[0-9]{3,4}'
        # http://81.293898
        - CommandLine|re: 'https?://[0-9]{1,3}\.0[0-9]{3,7}'
        # http://1359248394
        - CommandLine|re: 'https?://0[0-9]{3,11}'
        # http://0121.04.0174.012
        - CommandLine|re: 'https?://(0[0-9]{1,11}\.){3}0[0-9]{1,11}'
        # http://012101076012
        - CommandLine|re: 'https?://0[0-9]{1,11}'
        # For octal format
        - CommandLine|re: ' [0-7]{7,13}'
    filter_main_valid_ip:
        CommandLine|re: 'https?://((25[0-5]|(2[0-4]|1\d|[1-9])?\d)(\.|\b)){4}'
    condition: selection_img and 1 of selection_ip_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
