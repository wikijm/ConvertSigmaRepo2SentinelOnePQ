```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\cmd.exe" or src.process.image.path contains "\\cscript.exe" or src.process.image.path contains "\\mshta.exe" or src.process.image.path contains "\\powershell_ise.exe" or src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe" or src.process.image.path contains "\\wscript.exe") and tgt.process.image.path contains "\\regsvr32.exe") and (not (src.process.image.path="C:\\Windows\\System32\\cmd.exe" and tgt.process.cmdline contains " /s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll"))))
```


# Original Sigma Rule:
```yaml
title: Scripting/CommandLine Process Spawned Regsvr32
id: ab37a6ec-6068-432b-a64e-2c7bf95b1d22
related:
    - id: 8e2b24c9-4add-46a0-b4bb-0057b4e6187d
      type: obsolete
status: test
description: Detects various command line and scripting engines/processes such as "PowerShell", "Wscript", "Cmd", etc. spawning a "regsvr32" instance.
references:
    - https://web.archive.org/web/20171001085340/https://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html
    - https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-26
tags:
    - attack.defense-evasion
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        Image|endswith: '\regsvr32.exe'
    filter_main_rpcproxy:
        ParentImage: C:\Windows\System32\cmd.exe
        CommandLine|endswith: ' /s C:\Windows\System32\RpcProxy\RpcProxy.dll'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate ".bat", ".hta", ".ps1" or ".vbs" scripts leverage legitimately often. Apply additional filter and exclusions as necessary
    - Some legitimate Windows services
level: medium # Can be reduced to low if you experience a ton of FP
```
