```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " --cpu-priority=" or tgt.process.cmdline contains "--donate-level=0" or tgt.process.cmdline contains " -o pool." or tgt.process.cmdline contains " --nicehash" or tgt.process.cmdline contains " --algo=rx/0 " or tgt.process.cmdline contains "stratum+tcp://" or tgt.process.cmdline contains "stratum+udp://" or tgt.process.cmdline contains "LS1kb25hdGUtbGV2ZWw9" or tgt.process.cmdline contains "0tZG9uYXRlLWxldmVsP" or tgt.process.cmdline contains "tLWRvbmF0ZS1sZXZlbD" or tgt.process.cmdline contains "c3RyYXR1bSt0Y3A6Ly" or tgt.process.cmdline contains "N0cmF0dW0rdGNwOi8v" or tgt.process.cmdline contains "zdHJhdHVtK3RjcDovL" or tgt.process.cmdline contains "c3RyYXR1bSt1ZHA6Ly" or tgt.process.cmdline contains "N0cmF0dW0rdWRwOi8v" or tgt.process.cmdline contains "zdHJhdHVtK3VkcDovL") and (not (tgt.process.cmdline contains " pool.c " or tgt.process.cmdline contains " pool.o " or tgt.process.cmdline contains "gcc -"))))
```


# Original Sigma Rule:
```yaml
title: Potential Crypto Mining Activity
id: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
status: stable
description: Detects command line parameters or strings often used by crypto miners
references:
    - https://www.poolwatch.io/coin/monero
author: Florian Roth (Nextron Systems)
date: 2021-10-26
modified: 2023-02-13
tags:
    - attack.impact
    - attack.t1496
logsource:
    category: process_creation
    product: windows
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
    filter:
        CommandLine|contains:
            - ' pool.c '
            - ' pool.o '
            - 'gcc -'
    condition: selection and not filter
falsepositives:
    - Legitimate use of crypto miners
    - Some build frameworks
level: high
```
