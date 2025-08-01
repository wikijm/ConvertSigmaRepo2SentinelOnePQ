```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/git" and tgt.process.cmdline contains " clone ") and (tgt.process.cmdline contains "exploit" or tgt.process.cmdline contains "Vulns" or tgt.process.cmdline contains "vulnerability" or tgt.process.cmdline contains "RCE" or tgt.process.cmdline contains "RemoteCodeExecution" or tgt.process.cmdline contains "Invoke-" or tgt.process.cmdline contains "CVE-" or tgt.process.cmdline contains "poc-" or tgt.process.cmdline contains "ProofOfConcept" or tgt.process.cmdline contains "proxyshell" or tgt.process.cmdline contains "log4shell" or tgt.process.cmdline contains "eternalblue" or tgt.process.cmdline contains "eternal-blue" or tgt.process.cmdline contains "MS17-")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Git Clone - Linux
id: cfec9d29-64ec-4a0f-9ffe-0fdb856d5446
status: test
description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
references:
    - https://gist.githubusercontent.com/MichaelKoczwara/12faba9c061c12b5814b711166de8c2f/raw/e2068486692897b620c25fde1ea258c8218fe3d3/history.txt
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-03
modified: 2023-01-05
tags:
    - attack.reconnaissance
    - attack.t1593.003
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/git'
        CommandLine|contains: ' clone '
    selection_keyword:
        CommandLine|contains:
            # Add more suspicious keywords
            - 'exploit'
            - 'Vulns'
            - 'vulnerability'
            - 'RCE'
            - 'RemoteCodeExecution'
            - 'Invoke-'
            - 'CVE-'
            - 'poc-'
            - 'ProofOfConcept'
            # Add more vuln names
            - 'proxyshell'
            - 'log4shell'
            - 'eternalblue'
            - 'eternal-blue'
            - 'MS17-'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
