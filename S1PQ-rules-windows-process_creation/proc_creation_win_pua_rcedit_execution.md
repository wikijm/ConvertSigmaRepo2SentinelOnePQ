```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\rcedit-x64.exe" or tgt.process.image.path contains "\rcedit-x86.exe") or tgt.process.displayName="Edit resources of exe" or tgt.process.displayName="rcedit") and tgt.process.cmdline contains "--set-" and (tgt.process.cmdline contains "OriginalFileName" or tgt.process.cmdline contains "CompanyName" or tgt.process.cmdline contains "FileDescription" or tgt.process.cmdline contains "ProductName" or tgt.process.cmdline contains "ProductVersion" or tgt.process.cmdline contains "LegalCopyright")))
```


# Original Sigma Rule:
```yaml
title: PUA - Potential PE Metadata Tamper Using Rcedit
id: 0c92f2e6-f08f-4b73-9216-ecb0ca634689
status: test
description: Detects the use of rcedit to potentially alter executable PE metadata properties, which could conceal efforts to rename system utilities for defense evasion.
references:
    - https://security.stackexchange.com/questions/210843/is-it-possible-to-change-original-filename-of-an-exe
    - https://www.virustotal.com/gui/file/02e8e8c5d430d8b768980f517b62d7792d690982b9ba0f7e04163cbc1a6e7915
    - https://github.com/electron/rcedit
author: Micah Babinski
date: 2022-12-11
modified: 2023-03-05
tags:
    - attack.defense-evasion
    - attack.t1036.003
    - attack.t1036
    - attack.t1027.005
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\rcedit-x64.exe'
              - '\rcedit-x86.exe'
        - Description: 'Edit resources of exe'
        - Product: 'rcedit'
    selection_flags:
        CommandLine|contains: '--set-' # Covers multiple edit commands such as "--set-resource-string" or "--set-version-string"
    selection_attributes:
        CommandLine|contains:
            - 'OriginalFileName'
            - 'CompanyName'
            - 'FileDescription'
            - 'ProductName'
            - 'ProductVersion'
            - 'LegalCopyright'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the tool by administrators or users to update metadata of a binary
level: medium
```
