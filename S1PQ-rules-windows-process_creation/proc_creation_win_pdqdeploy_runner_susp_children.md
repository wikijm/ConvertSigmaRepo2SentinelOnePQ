```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\PDQDeployRunner-" and ((tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\csc.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\dllhost.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\scriptrunner.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\wsl.exe") or (tgt.process.image.path contains ":\\ProgramData\\" or tgt.process.image.path contains ":\\Users\\Public\\" or tgt.process.image.path contains ":\\Windows\\TEMP\\" or tgt.process.image.path contains "\\AppData\\Local\\Temp") or (tgt.process.cmdline contains " -decode " or tgt.process.cmdline contains " -enc " or tgt.process.cmdline contains " -encodedcommand " or tgt.process.cmdline contains " -w hidden" or tgt.process.cmdline contains "DownloadString" or tgt.process.cmdline contains "FromBase64String" or tgt.process.cmdline contains "http" or tgt.process.cmdline contains "iex " or tgt.process.cmdline contains "Invoke-"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Execution Of PDQDeployRunner
id: 12b8e9f5-96b2-41e1-9a42-8c6779a5c184
related:
    - id: d679950c-abb7-43a6-80fb-2a480c4fc450
      type: similar
status: test
description: Detects suspicious execution of "PDQDeployRunner" which is part of the PDQDeploy service stack that is responsible for executing commands and packages on a remote machines
references:
    - https://twitter.com/malmoeb/status/1550483085472432128
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-22
modified: 2024-05-02
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|contains: '\PDQDeployRunner-'
    selection_child:
        # Improve this section by adding other suspicious processes, commandlines or paths
        - Image|endswith:
              # If you use any of the following processes legitimately comment them out
              - '\bash.exe'
              - '\certutil.exe'
              - '\cmd.exe'
              - '\csc.exe'
              - '\cscript.exe'
              - '\dllhost.exe'
              - '\mshta.exe'
              - '\msiexec.exe'
              - '\regsvr32.exe'
              - '\rundll32.exe'
              - '\scriptrunner.exe'
              - '\wmic.exe'
              - '\wscript.exe'
              - '\wsl.exe'
        - Image|contains:
              - ':\ProgramData\'
              - ':\Users\Public\'
              - ':\Windows\TEMP\'
              - '\AppData\Local\Temp'
        - CommandLine|contains:
              - ' -decode '
              - ' -enc '
              - ' -encodedcommand '
              - ' -w hidden'
              - 'DownloadString'
              - 'FromBase64String'
              - 'http'
              - 'iex '
              - 'Invoke-'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the PDQDeploy tool to execute these commands
level: medium
```
