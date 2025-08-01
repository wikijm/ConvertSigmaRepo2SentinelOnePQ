```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\rpcping.exe" and (tgt.process.cmdline contains "-s" or tgt.process.cmdline contains "/s" or tgt.process.cmdline contains "–s" or tgt.process.cmdline contains "—s" or tgt.process.cmdline contains "―s") and (((tgt.process.cmdline contains "-u" or tgt.process.cmdline contains "/u" or tgt.process.cmdline contains "–u" or tgt.process.cmdline contains "—u" or tgt.process.cmdline contains "―u") and (tgt.process.cmdline contains "NTLM")) or ((tgt.process.cmdline contains "-t" or tgt.process.cmdline contains "/t" or tgt.process.cmdline contains "–t" or tgt.process.cmdline contains "—t" or tgt.process.cmdline contains "―t") and (tgt.process.cmdline contains "ncacn_np")))))
```


# Original Sigma Rule:
```yaml
title: Capture Credentials with Rpcping.exe
id: 93671f99-04eb-4ab4-a161-70d446a84003
status: test
description: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Rpcping/
    - https://twitter.com/vysecurity/status/974806438316072960
    - https://twitter.com/vysecurity/status/873181705024266241
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875578(v=ws.11)
author: Julia Fomina, oscd.community
date: 2020-10-09
modified: 2024-03-13
tags:
    - attack.credential-access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    use_rpcping:
        Image|endswith: '\rpcping.exe'
    remote_server:
        CommandLine|contains|windash: '-s'
    ntlm_auth:
        - CommandLine|contains|all|windash:
              - '-u'
              - 'NTLM'
        - CommandLine|contains|all|windash:
              - '-t'
              - 'ncacn_np'
    condition: use_rpcping and remote_server and ntlm_auth
falsepositives:
    - Unlikely
level: medium
```
