```sql
// Translated content (automatically translated on 26-12-2024 01:19:01):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\rar.exe" or tgt.process.image.path contains "\winrar.exe") or tgt.process.displayName="Command line RAR") and (not (tgt.process.image.path contains "\UnRAR.exe" or (tgt.process.image.path contains ":\Program Files (x86)\WinRAR\" or tgt.process.image.path contains ":\Program Files\WinRAR\"))) and (not tgt.process.image.path contains ":\Windows\Temp\")))
```


# Original Sigma Rule:
```yaml
title: Winrar Execution in Non-Standard Folder
id: 4ede543c-e098-43d9-a28f-dd784a13132f
status: test
description: Detects a suspicious winrar execution in a folder which is not the default installation folder
references:
    - https://twitter.com/cyb3rops/status/1460978167628406785
author: Florian Roth (Nextron Systems), Tigzy
date: 2021-11-17
modified: 2023-08-31
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\rar.exe'
              - '\winrar.exe'
        - Description: 'Command line RAR'
    filter_main_unrar:
        # Note: we filter unrar as it has the same description as the other utilities, and we're only interested in compression
        Image|endswith: '\UnRAR.exe'
    filter_main_path:
        Image|contains:
            - ':\Program Files (x86)\WinRAR\'
            - ':\Program Files\WinRAR\'
    filter_optional_temp:
        # Note: in some occasion installers were seen dropping "rar" in TEMP
        Image|contains: ':\Windows\Temp\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate use of WinRAR in a folder of a software that bundles WinRAR
level: medium
```
