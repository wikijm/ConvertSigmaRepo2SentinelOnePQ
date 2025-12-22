```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains " --cpu-priority=" or tgt.process.cmdline contains "--donate-level=0" or tgt.process.cmdline contains " -o pool." or tgt.process.cmdline contains " --nicehash" or tgt.process.cmdline contains " --algo=rx/0 " or tgt.process.cmdline contains "stratum+tcp://" or tgt.process.cmdline contains "stratum+udp://" or tgt.process.cmdline contains "sh -c /sbin/modprobe msr allow_writes=on" or tgt.process.cmdline contains "LS1kb25hdGUtbGV2ZWw9" or tgt.process.cmdline contains "0tZG9uYXRlLWxldmVsP" or tgt.process.cmdline contains "tLWRvbmF0ZS1sZXZlbD" or tgt.process.cmdline contains "c3RyYXR1bSt0Y3A6Ly" or tgt.process.cmdline contains "N0cmF0dW0rdGNwOi8v" or tgt.process.cmdline contains "zdHJhdHVtK3RjcDovL" or tgt.process.cmdline contains "c3RyYXR1bSt1ZHA6Ly" or tgt.process.cmdline contains "N0cmF0dW0rdWRwOi8v" or tgt.process.cmdline contains "zdHJhdHVtK3VkcDovL"))
```


# Original Sigma Rule:
```yaml
title: Linux Crypto Mining Indicators
id: 9069ea3c-b213-4c52-be13-86506a227ab1
status: test
description: Detects command line parameters or strings often used by crypto miners
references:
    - https://www.poolwatch.io/coin/monero
author: Florian Roth (Nextron Systems)
date: 2021-10-26
modified: 2022-12-25
tags:
    - attack.impact
    - attack.t1496
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - ' --cpu-priority='
            - '--donate-level=0'
            - ' -o pool.'
            - ' --nicehash'
            - ' --algo=rx/0 '
            - 'stratum+tcp://'
            - 'stratum+udp://'
            # Sub process started by xmrig - the most popular Monero crypto miner - unknown if this causes any false positives
            - 'sh -c /sbin/modprobe msr allow_writes=on'
            # base64 encoded: --donate-level=
            - 'LS1kb25hdGUtbGV2ZWw9'
            - '0tZG9uYXRlLWxldmVsP'
            - 'tLWRvbmF0ZS1sZXZlbD'
            # base64 encoded: stratum+tcp:// and stratum+udp://
            - 'c3RyYXR1bSt0Y3A6Ly'
            - 'N0cmF0dW0rdGNwOi8v'
            - 'zdHJhdHVtK3RjcDovL'
            - 'c3RyYXR1bSt1ZHA6Ly'
            - 'N0cmF0dW0rdWRwOi8v'
            - 'zdHJhdHVtK3VkcDovL'
    condition: selection
falsepositives:
    - Legitimate use of crypto miners
level: high
```
