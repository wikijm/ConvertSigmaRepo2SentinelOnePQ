```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline="*ipconfig*|*find*" or tgt.process.cmdline="*net*|*find*" or tgt.process.cmdline="*netstat*|*find*" or tgt.process.cmdline="*ping*|*find*" or tgt.process.cmdline="*systeminfo*|*find*" or tgt.process.cmdline="*tasklist*|*find*" or tgt.process.cmdline="*whoami*|*find*"))
```


# Original Sigma Rule:
```yaml
title: Recon Command Output Piped To Findstr.EXE
id: ccb5742c-c248-4982-8c5c-5571b9275ad3
related:
    - id: fe63010f-8823-4864-a96b-a7b4a0f7b929
      type: derived
status: test
description: |
    Detects the execution of a potential recon command where the results are piped to "findstr". This is meant to trigger on inline calls of "cmd.exe" via the "/c" or "/k" for example.
    Attackers often time use this technique to extract specific information they require in their reconnaissance phase.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/02cb591f75064ffe1e0df9ac3ed5972a2e491c97/atomics/T1057/T1057.md#atomic-test-6---discover-specific-process---tasklist
    - https://www.hhs.gov/sites/default/files/manage-engine-vulnerability-sector-alert-tlpclear.pdf
    - https://www.trendmicro.com/en_us/research/22/d/spring4shell-exploited-to-deploy-cryptocurrency-miners.html
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2023-07-06
modified: 2024-06-27
tags:
    - attack.discovery
    - attack.t1057
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # Note: Add additional CLI to increase and enhance coverage
            # Note: We use wildcards in this instance to avoid writing a lot of variations that can be avoided easily. You can switch to regex if its supported by your backend.
            - 'ipconfig*|*find'
            - 'net*|*find'
            - 'netstat*|*find'
            - 'ping*|*find'
            - 'systeminfo*|*find'
            - 'tasklist*|*find'
            - 'whoami*|*find'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
