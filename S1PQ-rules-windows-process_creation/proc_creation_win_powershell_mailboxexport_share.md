```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "New-MailboxExportRequest" and tgt.process.cmdline contains " -Mailbox " and tgt.process.cmdline contains " -FilePath \\\\"))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell Mailbox Export to Share
id: 889719ef-dd62-43df-86c3-768fb08dc7c0
status: test
description: Detects usage of the powerShell New-MailboxExportRequest Cmdlet to exports a mailbox to a remote or local share, as used in ProxyShell exploitations
references:
    - https://youtu.be/5mqid-7zp8k?t=2481
    - https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
    - https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1
    - https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/
author: Florian Roth (Nextron Systems)
date: 2021-08-07
modified: 2022-10-26
tags:
    - attack.exfiltration
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'New-MailboxExportRequest'
            - ' -Mailbox '
            - ' -FilePath \\\\'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
