```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\chrome.exe" or src.process.image.path contains "\\discord.exe" or src.process.image.path contains "\\GitHubDesktop.exe" or src.process.image.path contains "\\keybase.exe" or src.process.image.path contains "\\msedge.exe" or src.process.image.path contains "\\msedgewebview2.exe" or src.process.image.path contains "\\msteams.exe" or src.process.image.path contains "\\slack.exe" or src.process.image.path contains "\\teams.exe") and ((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\wscript.exe") or (tgt.process.image.path contains ":\\ProgramData\\" or tgt.process.image.path contains ":\\Temp\\" or tgt.process.image.path contains "\\AppData\\Local\\Temp\\" or tgt.process.image.path contains "\\Users\\Public\\" or tgt.process.image.path contains "\\Windows\\Temp\\")) and (not (src.process.image.path contains "\\Discord.exe" and tgt.process.image.path contains "\\cmd.exe" and tgt.process.cmdline contains "\\NVSMI\\nvidia-smi.exe"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Electron Application Child Processes
id: f26eb764-fd89-464b-85e2-dc4a8e6e77b8
related:
    - id: 378a05d8-963c-46c9-bcce-13c7657eac99
      type: similar
status: test
description: |
    Detects suspicious child processes of electron apps (teams, discord, slack, etc.). This could be a potential sign of ".asar" file tampering (See reference section for more information) or binary execution proxy through specific CLI arguments (see related rule)
references:
    - https://taggart-tech.com/quasar-electron/
    - https://github.com/mttaggart/quasar
    - https://positive.security/blog/ms-officecmd-rce
    - https://lolbas-project.github.io/lolbas/Binaries/Msedge/
    - https://lolbas-project.github.io/lolbas/Binaries/Teams/
    - https://lolbas-project.github.io/lolbas/Binaries/msedgewebview2/
    - https://medium.com/@MalFuzzer/one-electron-to-rule-them-all-dc2e9b263daf
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-21
modified: 2024-07-12
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            # Add more electron based app to the list
            - '\chrome.exe' # Might require additional tuning
            - '\discord.exe'
            - '\GitHubDesktop.exe'
            - '\keybase.exe'
            - '\msedge.exe'
            - '\msedgewebview2.exe'
            - '\msteams.exe'
            - '\slack.exe'
            - '\teams.exe'
            # - '\code.exe' # Prone to a lot of FPs. Requires an additional baseline
    selection_child_image:
        Image|endswith:
            # Add more suspicious/unexpected paths
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\whoami.exe'
            - '\wscript.exe'
    selection_child_paths:
        Image|contains:
            # Add more suspicious/unexpected paths
            - ':\ProgramData\'
            - ':\Temp\'
            - '\AppData\Local\Temp\'
            - '\Users\Public\'
            - '\Windows\Temp\'
    filter_optional_discord:
        ParentImage|endswith: '\Discord.exe'
        Image|endswith: '\cmd.exe'
        CommandLine|contains: '\NVSMI\nvidia-smi.exe'
    condition: selection_parent and 1 of selection_child_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
# Increase the level once FP rate is reduced (see status)
level: medium
```
