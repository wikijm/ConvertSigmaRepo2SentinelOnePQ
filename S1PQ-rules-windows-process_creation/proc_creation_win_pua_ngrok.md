```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " tcp 139" or tgt.process.cmdline contains " tcp 445" or tgt.process.cmdline contains " tcp 3389" or tgt.process.cmdline contains " tcp 5985" or tgt.process.cmdline contains " tcp 5986") or (tgt.process.cmdline contains " start " and tgt.process.cmdline contains "--all" and tgt.process.cmdline contains "--config" and tgt.process.cmdline contains ".yml") or (tgt.process.image.path contains "ngrok.exe" and (tgt.process.cmdline contains " tcp " or tgt.process.cmdline contains " http " or tgt.process.cmdline contains " authtoken ")) or (tgt.process.cmdline contains ".exe authtoken " or tgt.process.cmdline contains ".exe start --all")))
```


# Original Sigma Rule:
```yaml
title: PUA - Ngrok Execution
id: ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31
status: test
description: |
  Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
  Involved domains are bin.equinox.io for download and *.ngrok.io for connections.
references:
    - https://ngrok.com/docs
    - https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html
    - https://stackoverflow.com/questions/42442320/ssh-tunnel-to-ngrok-and-initiate-rdp
    - https://www.virustotal.com/gui/file/58d21840d915aaf4040ceb89522396124c82f325282f805d1085527e1e2ccfa1/detection
    - https://cybleinc.com/2021/02/15/ngrok-platform-abused-by-hackers-to-deliver-a-new-wave-of-phishing-attacks/
    - https://twitter.com/xorJosh/status/1598646907802451969
    - https://www.softwaretestinghelp.com/how-to-use-ngrok/
author: Florian Roth (Nextron Systems)
date: 2021-05-14
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - ' tcp 139'
            - ' tcp 445'
            - ' tcp 3389'
            - ' tcp 5985'
            - ' tcp 5986'
    selection2:
        CommandLine|contains|all:
            - ' start '
            - '--all'
            - '--config'
            - '.yml'
    selection3:
        Image|endswith: 'ngrok.exe'
        CommandLine|contains:
            - ' tcp '
            - ' http '
            - ' authtoken '
    selection4:
        CommandLine|contains:
            - '.exe authtoken '
            - '.exe start --all'
    condition: 1 of selection*
falsepositives:
    - Another tool that uses the command line switches of Ngrok
    - Ngrok http 3978 (https://learn.microsoft.com/en-us/azure/bot-service/bot-service-debug-channel-ngrok?view=azure-bot-service-4.0)
level: high
```
