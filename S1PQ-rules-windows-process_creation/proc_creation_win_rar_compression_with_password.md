```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " -hp" and (tgt.process.cmdline contains " -m" or tgt.process.cmdline contains " a ")))
```


# Original Sigma Rule:
```yaml
title: Rar Usage with Password and Compression Level
id: faa48cae-6b25-4f00-a094-08947fef582f
status: test
description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.
references:
    - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
    - https://ss64.com/bash/rar.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: '@ROxPinTeddy'
date: 2020-05-12
modified: 2022-03-16
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_password:
        CommandLine|contains: ' -hp'
    selection_other:
        CommandLine|contains:
            - ' -m'
            - ' a '
    condition: selection_password and selection_other
falsepositives:
    - Legitimate use of Winrar command line version
    - Other command line tools, that use these flags
level: high
```
