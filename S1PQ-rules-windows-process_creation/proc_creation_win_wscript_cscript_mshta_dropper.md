```sql
// Translated content (automatically translated on 07-09-2026 04:13:05):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe") and (tgt.process.cmdline contains ":\\Perflogs\\" or tgt.process.cmdline contains ":\\Temp\\" or tgt.process.cmdline contains ":\\Tmp\\" or tgt.process.cmdline contains ":\\Users\\Public\\" or tgt.process.cmdline contains ":\\Windows\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Local\\Temp\\" or tgt.process.cmdline contains "\\AppData\\Roaming\\Temp\\" or tgt.process.cmdline contains "\\Start Menu\\Programs\\Startup\\" or tgt.process.cmdline contains "\\Temporary Internet" or tgt.process.cmdline contains "\\Windows\\Temp" or tgt.process.cmdline contains "%LocalAppData%\\Temp\\" or tgt.process.cmdline contains "%TEMP%" or tgt.process.cmdline contains "%TMP%") and (tgt.process.cmdline contains ".hta" or tgt.process.cmdline contains ".js" or tgt.process.cmdline contains ".jse" or tgt.process.cmdline contains ".vba" or tgt.process.cmdline contains ".vbe" or tgt.process.cmdline contains ".vbs" or tgt.process.cmdline contains ".wsf" or tgt.process.cmdline contains ".wsh")))
```


# Original Sigma Rule:
```yaml
title: Potential Dropper Script Execution Via WScript/CScript/MSHTA
id: cea72823-df4d-4567-950c-0b579eaf0846
related:
    - id: 1e33157c-53b1-41ad-bbcc-780b80b58288
      type: similar
status: test
description: Detects wscript/cscript/mshta executions of scripts located in user directories
references:
    - https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
    - https://redcanary.com/blog/gootloader/
    - https://www.microsoft.com/en-us/security/blog/2025/03/06/malvertising-campaign-leads-to-info-stealers-hosted-on-github/
author: Margaritis Dimitrios (idea), Florian Roth (Nextron Systems), oscd.community, Nasreddine Bencherchali (Nextron Systems), Dave Johnson
date: 2019-01-16
modified: 2026-02-17
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_exec:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    selection_paths:
        CommandLine|contains:
            - ':\Perflogs\'
            - ':\Temp\'
            - ':\Tmp\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\Temp\'
            - '\Start Menu\Programs\Startup\'
            - '\Temporary Internet'
            - '\Windows\Temp'
            - '%LocalAppData%\Temp\'
            - '%TEMP%'
            - '%TMP%'
    selection_ext:
        CommandLine|contains:
            - '.hta'
            - '.js'
            - '.jse'
            - '.vba'
            - '.vbe'
            - '.vbs'
            - '.wsf'
            - '.wsh'
    condition: all of selection_*
falsepositives:
    - Some installers might generate a similar behavior. An initial baseline is required
level: medium
```
