```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "--config " and tgt.process.cmdline contains "--no-check-certificate " and tgt.process.cmdline contains " copy ") or ((tgt.process.image.path contains "\\rclone.exe" or tgt.process.displayName="Rsync for cloud storage") and (tgt.process.cmdline contains "pass" or tgt.process.cmdline contains "user" or tgt.process.cmdline contains "copy" or tgt.process.cmdline contains "sync" or tgt.process.cmdline contains "config" or tgt.process.cmdline contains "lsd" or tgt.process.cmdline contains "remote" or tgt.process.cmdline contains "ls" or tgt.process.cmdline contains "mega" or tgt.process.cmdline contains "pcloud" or tgt.process.cmdline contains "ftp" or tgt.process.cmdline contains "ignore-existing" or tgt.process.cmdline contains "auto-confirm" or tgt.process.cmdline contains "transfers" or tgt.process.cmdline contains "multi-thread-streams" or tgt.process.cmdline contains "no-check-certificate "))))
```


# Original Sigma Rule:
```yaml
title: PUA - Rclone Execution
id: e37db05d-d1f9-49c8-b464-cee1a4b11638
related:
    - id: a0d63692-a531-4912-ad39-4393325b2a9c
      type: obsolete
    - id: cb7286ba-f207-44ab-b9e6-760d82b84253
      type: obsolete
status: test
description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a
    - https://labs.sentinelone.com/egregor-raas-continues-the-chaos-with-cobalt-strike-and-rclone
    - https://www.splunk.com/en_us/blog/security/darkside-ransomware-splunk-threat-update-and-detections.html
author: Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group
date: 2021-05-10
modified: 2023-03-05
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_specific_options:
        CommandLine|contains|all:
            - '--config '
            - '--no-check-certificate '
            - ' copy '
    selection_rclone_img:
        - Image|endswith: '\rclone.exe'
        - Description: 'Rsync for cloud storage'
    selection_rclone_cli:
        CommandLine|contains:
            - 'pass'
            - 'user'
            - 'copy'
            - 'sync'
            - 'config'
            - 'lsd'
            - 'remote'
            - 'ls'
            - 'mega'
            - 'pcloud'
            - 'ftp'
            - 'ignore-existing'
            - 'auto-confirm'
            - 'transfers'
            - 'multi-thread-streams'
            - 'no-check-certificate '
    condition: selection_specific_options or all of selection_rclone_*
falsepositives:
    - Unknown
level: high
```
