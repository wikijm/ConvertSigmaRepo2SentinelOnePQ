```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\BitLockerToGo.exe")
```


# Original Sigma Rule:
```yaml
title: BitLockerTogo.EXE Execution
id: 7f2376f9-42ee-4dfc-9360-fecff9a88fc8
status: test
description: |
    Detects the execution of "BitLockerToGo.EXE".
    BitLocker To Go is BitLocker Drive Encryption on removable data drives. This feature includes the encryption of, USB flash drives, SD cards, External hard disk drives, Other drives that are formatted by using the NTFS, FAT16, FAT32, or exFAT file system.
    This is a rarely used application and usage of it at all is worth investigating.
    Malware such as Lumma stealer has been seen using this process as a target for process hollowing.
references:
    - https://tria.ge/240521-ynezpagf56/behavioral1
    - https://any.run/report/6eea2773c1b4b5c6fb7c142933e220c96f9a4ec89055bf0cf54accdcde7df535/a407f006-ee45-420d-b576-f259094df091
    - https://bazaar.abuse.ch/sample/8c75f8e94486f5bbf461505823f5779f328c5b37f1387c18791e0c21f3fdd576/
    - https://bazaar.abuse.ch/sample/64e6605496919cd76554915cbed88e56fdec10dec6523918a631754664b8c8d3/
author: Josh Nickels, mttaggart
date: 2024-07-11
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\BitLockerToGo.exe'
    condition: selection
falsepositives:
    - Legitimate usage of BitLockerToGo.exe to encrypt portable devices.
level: low
```
