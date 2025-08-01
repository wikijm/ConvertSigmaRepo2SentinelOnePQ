```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains ".SettingContent-ms" and (not tgt.process.cmdline contains "immersivecontrolpanel"))) | columns ParentProcess,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Arbitrary Shell Command Execution Via Settingcontent-Ms
id: 24de4f3b-804c-4165-b442-5a06a2302c7e
status: test
description: The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create "shortcuts" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.
references:
    - https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
author: Sreeman
date: 2020-03-13
modified: 2022-04-14
tags:
    - attack.t1204
    - attack.t1566.001
    - attack.execution
    - attack.initial-access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '.SettingContent-ms'
    filter:
        CommandLine|contains: 'immersivecontrolpanel'
    condition: selection and not filter
fields:
    - ParentProcess
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium
```
