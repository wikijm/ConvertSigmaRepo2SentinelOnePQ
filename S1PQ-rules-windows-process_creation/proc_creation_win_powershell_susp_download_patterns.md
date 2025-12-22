```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "IEX ((New-Object Net.WebClient).DownloadString" or tgt.process.cmdline contains "IEX (New-Object Net.WebClient).DownloadString" or tgt.process.cmdline contains "IEX((New-Object Net.WebClient).DownloadString" or tgt.process.cmdline contains "IEX(New-Object Net.WebClient).DownloadString" or tgt.process.cmdline contains " -command (New-Object System.Net.WebClient).DownloadFile(" or tgt.process.cmdline contains " -c (New-Object System.Net.WebClient).DownloadFile("))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell Download and Execute Pattern
id: e6c54d94-498c-4562-a37c-b469d8e9a275
related:
    - id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
      type: derived
status: test
description: Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)
references:
    - https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
    - https://www.trendmicro.com/en_us/research/22/j/lv-ransomware-exploits-proxyshell-in-attack.html
author: Florian Roth (Nextron Systems)
date: 2022-02-28
modified: 2022-03-01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: # make sure that your backend applies the strings case-insensitive
            - 'IEX ((New-Object Net.WebClient).DownloadString'
            - 'IEX (New-Object Net.WebClient).DownloadString'
            - 'IEX((New-Object Net.WebClient).DownloadString'
            - 'IEX(New-Object Net.WebClient).DownloadString'
            - ' -command (New-Object System.Net.WebClient).DownloadFile('
            - ' -c (New-Object System.Net.WebClient).DownloadFile('
    condition: selection
falsepositives:
    - Software installers that pull packages from remote systems and execute them
level: high
```
