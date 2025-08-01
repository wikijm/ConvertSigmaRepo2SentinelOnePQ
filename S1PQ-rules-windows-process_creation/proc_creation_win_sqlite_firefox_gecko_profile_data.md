```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.displayName="SQLite" or (tgt.process.image.path contains "\sqlite.exe" or tgt.process.image.path contains "\sqlite3.exe")) and (tgt.process.cmdline contains "cookies.sqlite" or tgt.process.cmdline contains "places.sqlite")))
```


# Original Sigma Rule:
```yaml
title: SQLite Firefox Profile Data DB Access
id: 4833155a-4053-4c9c-a997-777fcea0baa7
status: test
description: Detect usage of the "sqlite" binary to query databases in Firefox and other Gecko-based browsers for potential data stealing.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1539/T1539.md#atomic-test-1---steal-firefox-cookies-windows
    - https://blog.cyble.com/2022/04/21/prynt-stealer-a-new-info-stealer-performing-clipper-and-keylogger-activities/
author: frack113
date: 2022-04-08
modified: 2023-01-19
tags:
    - attack.credential-access
    - attack.t1539
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_sql:
        - Product: SQLite
        - Image|endswith:
              - '\sqlite.exe'
              - '\sqlite3.exe'
    selection_firefox:
        CommandLine|contains:
            - 'cookies.sqlite'
            - 'places.sqlite' # Bookmarks, history
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
