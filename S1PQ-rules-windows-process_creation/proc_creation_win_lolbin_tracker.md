```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\tracker.exe" or tgt.process.displayName="Tracker") and (tgt.process.cmdline contains " /d " or tgt.process.cmdline contains " /c ")) and (not (tgt.process.cmdline contains " /ERRORREPORT:PROMPT " or (src.process.image.path contains "\\Msbuild\\Current\\Bin\\MSBuild.exe" or src.process.image.path contains "\\Msbuild\\Current\\Bin\\amd64\\MSBuild.exe")))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Injection Or Execution Using Tracker.exe
id: 148431ce-4b70-403d-8525-fcc2993f29ea
status: test
description: Detects potential DLL injection and execution using "Tracker.exe"
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/
author: 'Avneet Singh @v3t0_, oscd.community'
date: 2020-10-18
modified: 2023-01-09
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.t1055.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\tracker.exe'
        - Description: 'Tracker'
    selection_cli:
        CommandLine|contains:
            - ' /d '
            - ' /c '
    filter_msbuild1:
        CommandLine|contains: ' /ERRORREPORT:PROMPT '
    filter_msbuild2:
        # Example:
        #   GrandparentImage: C:\Program Files\Microsoft Visual Studio\2022\Community\Msbuild\Current\Bin\MSBuild.exe
        #   ParentCommandLine: "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" /nologo /nodemode:1 /nodeReuse:true /low:false
        #   CommandLine: "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Tracker.exe" @"C:\Users\user\AppData\Local\Temp\tmp05c7789bc5534838bf96d7a0fed1ffff.tmp" /c "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.29.30133\bin\HostX86\x64\Lib.exe"
        ParentImage|endswith:
            - '\Msbuild\Current\Bin\MSBuild.exe'
            - '\Msbuild\Current\Bin\amd64\MSBuild.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
