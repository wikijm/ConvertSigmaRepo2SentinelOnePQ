```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\mshta.exe" or src.process.image.path contains "\\powershell.exe" or src.process.image.path contains "\\pwsh.exe" or src.process.image.path contains "\\rundll32.exe" or src.process.image.path contains "\\cscript.exe" or src.process.image.path contains "\\wscript.exe" or src.process.image.path contains "\\wmiprvse.exe" or src.process.image.path contains "\\regsvr32.exe") and (tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\nslookup.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\mshta.exe")) and (not (tgt.process.image.path contains "\\ccmcache\\" or (src.process.cmdline contains "\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\setup-scheduledtask.ps1" or src.process.cmdline contains "\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\set-selfhealing.ps1" or src.process.cmdline contains "\\Program Files\\Amazon\\WorkSpacesConfig\\Scripts\\check-workspacehealth.ps1" or src.process.cmdline contains "\\nessus_") or tgt.process.cmdline contains "\\nessus_" or (src.process.image.path contains "\\mshta.exe" and tgt.process.image.path contains "\\mshta.exe" and (src.process.cmdline contains "C:\\MEM_Configmgr_" and src.process.cmdline contains "\\splash.hta" and src.process.cmdline contains "{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}") and (tgt.process.cmdline contains "C:\\MEM_Configmgr_" and tgt.process.cmdline contains "\\SMSSETUP\\BIN\\" and tgt.process.cmdline contains "\\autorun.hta" and tgt.process.cmdline contains "{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}"))))))
```


# Original Sigma Rule:
```yaml
title: Windows Shell/Scripting Processes Spawning Suspicious Programs
id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
status: test
description: Detects suspicious child processes of a Windows shell and scripting processes such as wscript, rundll32, powershell, mshta...etc.
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Florian Roth (Nextron Systems), Tim Shelton
date: 2018-04-06
modified: 2023-05-23
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059.005
    - attack.t1059.001
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            # - '\cmd.exe'  # too many false positives
            - '\rundll32.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\wmiprvse.exe'
            - '\regsvr32.exe'
        Image|endswith:
            - '\schtasks.exe'
            - '\nslookup.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
    filter_ccmcache:
        CurrentDirectory|contains: '\ccmcache\'
    filter_amazon:
        ParentCommandLine|contains:
            # FP - Amazon Workspaces
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\setup-scheduledtask.ps1'
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\set-selfhealing.ps1'
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\check-workspacehealth.ps1'
            - '\nessus_' # Tenable/Nessus VA Scanner
    filter_nessus:
        CommandLine|contains: '\nessus_' # Tenable/Nessus VA Scanner
    filter_sccm_install:
        ParentImage|endswith: '\mshta.exe'
        Image|endswith: '\mshta.exe'
        ParentCommandLine|contains|all:
            - 'C:\MEM_Configmgr_'
            - '\splash.hta'
            - '{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}'
        CommandLine|contains|all:
            - 'C:\MEM_Configmgr_'
            - '\SMSSETUP\BIN\'
            - '\autorun.hta'
            - '{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}'
    condition: selection and not 1 of filter_*
falsepositives:
    - Administrative scripts
    - Microsoft SCCM
level: high
```
