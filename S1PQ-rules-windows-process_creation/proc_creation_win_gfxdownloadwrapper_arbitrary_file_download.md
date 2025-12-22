```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\GfxDownloadWrapper.exe" and (tgt.process.cmdline contains "http://" or tgt.process.cmdline contains "https://")) and (not tgt.process.cmdline contains "https://gameplayapi.intel.com/")))
```


# Original Sigma Rule:
```yaml
title: Arbitrary File Download Via GfxDownloadWrapper.EXE
id: eee00933-a761-4cd0-be70-c42fe91731e7
status: test
description: Detects execution of GfxDownloadWrapper.exe with a URL as an argument to download file.
references:
    - https://lolbas-project.github.io/lolbas/HonorableMentions/GfxDownloadWrapper/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2023-10-18
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GfxDownloadWrapper.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
    filter_main_known_urls:
        CommandLine|contains: 'https://gameplayapi.intel.com/'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
