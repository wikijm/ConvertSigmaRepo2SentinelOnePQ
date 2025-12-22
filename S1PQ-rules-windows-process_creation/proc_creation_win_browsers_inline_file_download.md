```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "http" and ((tgt.process.cmdline contains ".7z" or tgt.process.cmdline contains ".dat" or tgt.process.cmdline contains ".dll" or tgt.process.cmdline contains ".exe" or tgt.process.cmdline contains ".hta" or tgt.process.cmdline contains ".ps1" or tgt.process.cmdline contains ".psm1" or tgt.process.cmdline contains ".txt" or tgt.process.cmdline contains ".vbe" or tgt.process.cmdline contains ".vbs" or tgt.process.cmdline contains ".zip") or (tgt.process.cmdline contains ".7z\"" or tgt.process.cmdline contains ".dat\"" or tgt.process.cmdline contains ".dll\"" or tgt.process.cmdline contains ".hta\"" or tgt.process.cmdline contains ".ps1\"" or tgt.process.cmdline contains ".psm1\"" or tgt.process.cmdline contains ".txt\"" or tgt.process.cmdline contains ".vbe\"" or tgt.process.cmdline contains ".vbs\"" or tgt.process.cmdline contains ".zip\""))))
```


# Original Sigma Rule:
```yaml
title: File Download From Browser Process Via Inline URL
id: 94771a71-ba41-4b6e-a757-b531372eaab6
status: test
description: Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.
references:
    - https://twitter.com/mrd0x/status/1478116126005641220
    - https://lolbas-project.github.io/lolbas/Binaries/Msedge/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-01-11
modified: 2025-10-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    selection_http:
        CommandLine|contains: 'http'
    selection_extensions:
        - CommandLine|endswith:
              - '.7z'
              - '.dat'
              - '.dll'
              - '.exe'
              - '.hta'
              - '.ps1'
              - '.psm1'
              - '.txt'
              - '.vbe'
              - '.vbs'
              - '.zip'
        - CommandLine|contains:
              - '.7z"'
              - '.dat"'
              - '.dll"'
              - '.hta"'
              - '.ps1"'
              - '.psm1"'
              - '.txt"'
              - '.vbe"'
              - '.vbs"'
              - '.zip"'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_inline_file_download/info.yml
```
