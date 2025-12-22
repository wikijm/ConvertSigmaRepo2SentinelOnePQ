```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "--headless" and (tgt.process.cmdline contains "://run.mocky" or tgt.process.cmdline contains "://mockbin")))
```


# Original Sigma Rule:
```yaml
title: Chromium Browser Headless Execution To Mockbin Like Site
id: 1c526788-0abe-4713-862f-b520da5e5316
status: test
description: Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).
references:
    - https://www.zscaler.com/blogs/security-research/steal-it-campaign
author: X__Junior (Nextron Systems)
date: 2023-09-11
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    selection_headless:
        CommandLine|contains: '--headless'
    selection_url:
        CommandLine|contains:
            - '://run.mocky'
            - '://mockbin'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_chromium_mockbin_abuse/info.yml
```
