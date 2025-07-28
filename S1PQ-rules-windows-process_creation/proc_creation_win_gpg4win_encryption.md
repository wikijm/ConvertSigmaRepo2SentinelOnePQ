```sql
// Translated content (automatically translated on 28-07-2025 02:27:57):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\gpg.exe" or tgt.process.image.path contains "\gpg2.exe") or tgt.process.displayName="GnuPG’s OpenPGP tool") and (tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "passphrase")))
```


# Original Sigma Rule:
```yaml
title: File Encryption Using Gpg4win
id: 550bbb84-ce5d-4e61-84ad-e590f0024dcd
status: test
description: Detects usage of Gpg4win to encrypt files
references:
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://www.gpg4win.de/documentation.html
    - https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-09
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_metadata:
        - Image|endswith:
              - '\gpg.exe'
              - '\gpg2.exe'
        - Description: 'GnuPG’s OpenPGP tool'
    selection_cli:
        CommandLine|contains|all:
            - ' -c '
            - 'passphrase'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
