```sql
// Translated content (automatically translated on 02-08-2025 01:37:53):
event.category="file" and (endpoint.os="osx" and ((tgt.file.path contains "/Library/StartupItems/" or tgt.file.path contains "/System/Library/StartupItems") and tgt.file.path contains ".plist"))
```


# Original Sigma Rule:
```yaml
title: Startup Item File Created - MacOS
id: dfe8b941-4e54-4242-b674-6b613d521962
status: test
description: |
    Detects the creation of a startup item plist file, that automatically get executed at boot initialization to establish persistence.
    Adversaries may use startup items automatically executed at boot initialization to establish persistence.
    Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1037.005/T1037.005.md
    - https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html
author: Alejandro Ortuno, oscd.community
date: 2020-10-14
modified: 2024-08-11
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1037.005
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|startswith:
            - '/Library/StartupItems/'
            - '/System/Library/StartupItems'
        TargetFilename|endswith: '.plist'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
