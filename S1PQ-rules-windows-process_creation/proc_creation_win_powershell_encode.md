```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and (tgt.process.cmdline contains " -e " or tgt.process.cmdline contains " -en " or tgt.process.cmdline contains " -enc " or tgt.process.cmdline contains " -enco" or tgt.process.cmdline contains " -ec ")) and (not (tgt.process.cmdline contains " -Encoding " or (src.process.image.path contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\" or src.process.image.path contains "\\gc_worker.exe")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution of Powershell with Base64
id: fb843269-508c-4b76-8b8d-88679db22ce7
status: test
description: Commandline to launch powershell with a base64 payload
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
    - https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
    - https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/
author: frack113
date: 2022-01-02
modified: 2023-01-05
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - \powershell.exe
            - \pwsh.exe
        CommandLine|contains:
            - ' -e '
            - ' -en '
            - ' -enc '
            - ' -enco'
            - ' -ec '
    filter_encoding:
        CommandLine|contains: ' -Encoding '
    filter_azure:
        ParentImage|contains:
            - 'C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\'
            - '\gc_worker.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
