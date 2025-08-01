```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.displayName="SQLite" or (tgt.process.image.path contains "\sqlite.exe" or tgt.process.image.path contains "\sqlite3.exe")) and (tgt.process.cmdline contains "\User Data\" or tgt.process.cmdline contains "\Opera Software\" or tgt.process.cmdline contains "\ChromiumViewer\") and (tgt.process.cmdline contains "Login Data" or tgt.process.cmdline contains "Cookies" or tgt.process.cmdline contains "Web Data" or tgt.process.cmdline contains "History" or tgt.process.cmdline contains "Bookmarks")))
```


# Original Sigma Rule:
```yaml
title: SQLite Chromium Profile Data DB Access
id: 24c77512-782b-448a-8950-eddb0785fc71
status: test
description: Detect usage of the "sqlite" binary to query databases in Chromium-based browsers for potential data stealing.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/84d9edaaaa2c5511144521b0e4af726d1c7276ce/atomics/T1539/T1539.md#atomic-test-2---steal-chrome-cookies-windows
    - https://blog.cyble.com/2022/04/21/prynt-stealer-a-new-info-stealer-performing-clipper-and-keylogger-activities/
author: TropChaud
date: 2022-12-19
modified: 2023-01-19
tags:
    - attack.credential-access
    - attack.t1539
    - attack.t1555.003
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
    selection_chromium:
        CommandLine|contains:
            - '\User Data\' # Most common folder for user profile data among Chromium browsers
            - '\Opera Software\' # Opera
            - '\ChromiumViewer\' # Sleipnir (Fenrir)
    selection_data:
        CommandLine|contains:
            - 'Login Data' # Passwords
            - 'Cookies'
            - 'Web Data' # Credit cards, autofill data
            - 'History'
            - 'Bookmarks'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
