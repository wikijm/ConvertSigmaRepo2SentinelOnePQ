```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\\Windows\\Installer\\" and tgt.process.image.path contains "msi") and tgt.process.image.path contains "tmp") or (tgt.process.image.path contains "\\msiexec.exe" and (tgt.process.integrityLevel in ("System","S-1-16-16384")))) and (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI") and (not (src.process.image.path="C:\\Windows\\System32\\services.exe" or (tgt.process.cmdline contains "\\system32\\msiexec.exe /V" or src.process.cmdline contains "\\system32\\msiexec.exe /V") or src.process.image.path contains "C:\\ProgramData\\Sophos\\" or src.process.image.path contains "C:\\ProgramData\\Avira\\" or (src.process.image.path contains "C:\\Program Files\\Avast Software\\" or src.process.image.path contains "C:\\Program Files (x86)\\Avast Software\\") or (src.process.image.path contains "C:\\Program Files\\Google\\Update\\" or src.process.image.path contains "C:\\Program Files (x86)\\Google\\Update\\")))))
```


# Original Sigma Rule:
```yaml
title: Always Install Elevated Windows Installer
id: cd951fdc-4b2f-47f5-ba99-a33bf61e3770
status: test
description: Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege
references:
    - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-48-638.jpg
author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
date: 2020-10-13
modified: 2024-12-01
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_user:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    selection_image_1:
        Image|contains|all:
            - '\Windows\Installer\'
            - 'msi'
        Image|endswith: 'tmp'
    selection_image_2:
        Image|endswith: '\msiexec.exe'
        IntegrityLevel:
            - 'System'
            - 'S-1-16-16384'
    filter_installer:
        ParentImage: 'C:\Windows\System32\services.exe'
    filter_repair:
        - CommandLine|endswith: '\system32\msiexec.exe /V' # ignore "repair option"
        - ParentCommandLine|endswith: '\system32\msiexec.exe /V' # ignore "repair option"
    filter_sophos:
        ParentImage|startswith: 'C:\ProgramData\Sophos\'
    filter_avira:
        ParentImage|startswith: 'C:\ProgramData\Avira\'
    filter_avast:
        ParentImage|startswith:
            - 'C:\Program Files\Avast Software\'
            - 'C:\Program Files (x86)\Avast Software\'
    filter_google_update:
        ParentImage|startswith:
            - 'C:\Program Files\Google\Update\'
            - 'C:\Program Files (x86)\Google\Update\'
    condition: 1 of selection_image_* and selection_user and not 1 of filter_*
falsepositives:
    - System administrator usage
    - Anti virus products
    - WindowsApps located in "C:\Program Files\WindowsApps\"
level: medium
```
