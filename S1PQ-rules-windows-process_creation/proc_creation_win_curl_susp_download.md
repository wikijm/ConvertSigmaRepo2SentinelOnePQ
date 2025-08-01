```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\curl.exe" or tgt.process.displayName="The curl executable") and ((tgt.process.cmdline contains "%AppData%" or tgt.process.cmdline contains "%Public%" or tgt.process.cmdline contains "%Temp%" or tgt.process.cmdline contains "%tmp%" or tgt.process.cmdline contains "\AppData\" or tgt.process.cmdline contains "\Desktop\" or tgt.process.cmdline contains "\Temp\" or tgt.process.cmdline contains "\Users\Public\" or tgt.process.cmdline contains "C:\PerfLogs\" or tgt.process.cmdline contains "C:\ProgramData\" or tgt.process.cmdline contains "C:\Windows\Temp\") or (tgt.process.cmdline contains ".dll" or tgt.process.cmdline contains ".gif" or tgt.process.cmdline contains ".jpeg" or tgt.process.cmdline contains ".jpg" or tgt.process.cmdline contains ".png" or tgt.process.cmdline contains ".temp" or tgt.process.cmdline contains ".tmp" or tgt.process.cmdline contains ".txt" or tgt.process.cmdline contains ".vbe" or tgt.process.cmdline contains ".vbs")) and (not (src.process.image.path="C:\Program Files\Git\usr\bin\sh.exe" and tgt.process.image.path="C:\Program Files\Git\mingw64\bin\curl.exe" and (tgt.process.cmdline contains "--silent --show-error --output " and tgt.process.cmdline contains "gfw-httpget-" and tgt.process.cmdline contains "AppData")))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Curl.EXE Download
id: e218595b-bbe7-4ee5-8a96-f32a24ad3468
related:
    - id: bbeaed61-1990-4773-bf57-b81dbad7db2d # Basic curl execution
      type: derived
    - id: 9a517fca-4ba3-4629-9278-a68694697b81 # Curl download
      type: similar
status: test
description: Detects a suspicious curl process start on Windows and outputs the requested document to a local file
references:
    - https://twitter.com/max_mal_/status/1542461200797163522
    - https://web.archive.org/web/20200128160046/https://twitter.com/reegun21/status/1222093798009790464
    - https://github.com/pr0xylife/Qakbot/blob/4f0795d79dabee5bc9dd69f17a626b48852e7869/Qakbot_AA_23.06.2022.txt
    - https://www.volexity.com/blog/2022/07/28/sharptongue-deploys-clever-mail-stealing-browser-extension-sharpext/
    - https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1105/T1105.md#atomic-test-18---curl-download-file
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2020-07-03
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        - Image|endswith: '\curl.exe'
        - Product: 'The curl executable'
    selection_susp_locations:
        CommandLine|contains:
            - '%AppData%'
            - '%Public%'
            - '%Temp%'
            - '%tmp%'
            - '\AppData\'
            - '\Desktop\'
            - '\Temp\'
            - '\Users\Public\'
            - 'C:\PerfLogs\'
            - 'C:\ProgramData\'
            - 'C:\Windows\Temp\'
    selection_susp_extensions:
        CommandLine|endswith:
            - '.dll'
            - '.gif'
            - '.jpeg'
            - '.jpg'
            - '.png'
            - '.temp'
            - '.tmp'
            - '.txt'
            - '.vbe'
            - '.vbs'
    filter_optional_git_windows:
        # Example FP
        #   CommandLine: "C:\Program Files\Git\mingw64\bin\curl.exe" --silent --show-error --output C:/Users/test/AppData/Local/Temp/gfw-httpget-jVOEoxbS.txt --write-out %{http_code} https://gitforwindows.org/latest-tag.txt
        ParentImage: 'C:\Program Files\Git\usr\bin\sh.exe'
        Image: 'C:\Program Files\Git\mingw64\bin\curl.exe'
        CommandLine|contains|all:
            - '--silent --show-error --output '
            - 'gfw-httpget-'
            - 'AppData'
    condition: selection_curl and 1 of selection_susp_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high
```
