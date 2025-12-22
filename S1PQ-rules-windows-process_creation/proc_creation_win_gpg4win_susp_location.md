```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\gpg.exe" or tgt.process.image.path contains "\\gpg2.exe") or tgt.process.displayName="GNU Privacy Guard (GnuPG)" or tgt.process.displayName="GnuPG’s OpenPGP tool") and tgt.process.cmdline contains "-passphrase" and (tgt.process.cmdline contains ":\\PerfLogs\\" or tgt.process.cmdline contains ":\\Temp\\" or tgt.process.cmdline contains ":\\Users\\Public\\" or tgt.process.cmdline contains ":\\Windows\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Local\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Roaming\\")))
```


# Original Sigma Rule:
```yaml
title: File Encryption/Decryption Via Gpg4win From Suspicious Locations
id: e1e0b7d7-e10b-4ee4-ac49-a4bda05d320d
status: test
description: Detects usage of Gpg4win to encrypt/decrypt files located in potentially suspicious locations.
references:
    - https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html
    - https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
author: Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)
date: 2022-11-30
modified: 2023-08-09
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
        - Product: 'GNU Privacy Guard (GnuPG)'
        - Description: 'GnuPG’s OpenPGP tool'
    selection_cli:
        CommandLine|contains: '-passphrase'
    selection_paths:
        CommandLine|contains:
            - ':\PerfLogs\'
            - ':\Temp\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
