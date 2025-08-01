```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\cmd.exe" and (tgt.process.cmdline contains "http" and tgt.process.cmdline contains "://" and tgt.process.cmdline contains "%AppData%"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Command Line Execution with Suspicious URL and AppData Strings
id: 1ac8666b-046f-4201-8aba-1951aaec03a3
status: test
description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
references:
    - https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
    - https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
date: 2019-01-16
modified: 2021-11-27
tags:
    - attack.execution
    - attack.command-and-control
    - attack.t1059.003
    - attack.t1059.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'http' # captures both http and https
            - '://'
            - '%AppData%'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - High
level: medium
```
