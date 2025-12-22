```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\Windows\\" and (tgt.process.cmdline contains "\\..\\Windows\\" or tgt.process.cmdline contains "\\..\\System32\\" or tgt.process.cmdline contains "\\..\\..\\")) or tgt.process.cmdline contains ".exe\\..\\") and (not (tgt.process.cmdline contains "\\Google\\Drive\\googledrivesync.exe\\..\\" or tgt.process.cmdline contains "\\Citrix\\Virtual Smart Card\\Citrix.Authentication.VirtualSmartcard.Launcher.exe\\..\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Command Line Path Traversal Evasion Attempt
id: 1327381e-6ab0-4f38-b583-4c1b8346a56b
status: test
description: Detects potential evasion or obfuscation attempts using bogus path traversal via the commandline
references:
    - https://twitter.com/hexacorn/status/1448037865435320323
    - https://twitter.com/Gal_B1t/status/1062971006078345217
author: Christian Burkard (Nextron Systems)
date: 2021-10-26
modified: 2023-03-29
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|contains: '\Windows\'
        CommandLine|contains:
            - '\..\Windows\'
            - '\..\System32\'
            - '\..\..\'
    selection_2:
        CommandLine|contains: '.exe\..\'
    filter_optional_google_drive:
        CommandLine|contains: '\Google\Drive\googledrivesync.exe\..\'
    filter_optional_citrix:
        CommandLine|contains: '\Citrix\Virtual Smart Card\Citrix.Authentication.VirtualSmartcard.Launcher.exe\..\'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Google Drive
    - Citrix
level: medium
```
