```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\odbcconf.exe")
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Spawned By Odbcconf.EXE
id: 8e3c7994-131e-4ba5-b6ea-804d49113a26
status: test
description: Detects an uncommon child process of "odbcconf.exe" binary which normally shouldn't have any child processes.
references:
    - https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
    - https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
    - https://medium.com/@cyberjyot/t1218-008-dll-execution-using-odbcconf-exe-803fa9e08dac
author: Harjot Singh @cyb3rjy0t
date: 2023-05-22
tags:
    - attack.defense-evasion
    - attack.t1218.008
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\odbcconf.exe'
    condition: selection
falsepositives:
    - In rare occurrences where "odbcconf" crashes. It might spawn a "werfault" process
    - Other child processes will depend on the DLL being registered by actions like "regsvr". In case where the DLLs have external calls (which should be rare). Other child processes might spawn and additional filters need to be applied.
level: medium
```
