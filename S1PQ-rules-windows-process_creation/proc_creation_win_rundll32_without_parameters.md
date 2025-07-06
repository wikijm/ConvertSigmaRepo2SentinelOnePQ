```sql
// Translated content (automatically translated on 06-07-2025 02:22:55):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline in ("rundll32.exe","rundll32"))) | columns ComputerName,SubjectUserName,tgt.process.cmdline,tgt.process.image.path,src.process.image.path
```


# Original Sigma Rule:
```yaml
title: Rundll32 Execution Without Parameters
id: 5bb68627-3198-40ca-b458-49f973db8752
status: test
description: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
references:
    - https://bczyz1.github.io/2021/01/30/psexec.html
author: Bartlomiej Czyz, Relativity
date: 2021-01-31
modified: 2023-02-28
tags:
    - attack.lateral-movement
    - attack.t1021.002
    - attack.t1570
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'rundll32.exe'
            - 'rundll32'
    condition: selection
fields:
    - ComputerName
    - SubjectUserName
    - CommandLine
    - Image
    - ParentImage
falsepositives:
    - False positives may occur if a user called rundll32 from CLI with no options
level: high
```
