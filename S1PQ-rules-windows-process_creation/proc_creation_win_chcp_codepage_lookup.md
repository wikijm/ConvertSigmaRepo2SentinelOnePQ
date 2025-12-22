```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\cmd.exe" and (src.process.cmdline contains " -c " or src.process.cmdline contains " /c " or src.process.cmdline contains " –c " or src.process.cmdline contains " —c " or src.process.cmdline contains " ―c " or src.process.cmdline contains " -r " or src.process.cmdline contains " /r " or src.process.cmdline contains " –r " or src.process.cmdline contains " —r " or src.process.cmdline contains " ―r " or src.process.cmdline contains " -k " or src.process.cmdline contains " /k " or src.process.cmdline contains " –k " or src.process.cmdline contains " —k " or src.process.cmdline contains " ―k ") and tgt.process.image.path contains "\\chcp.com" and (tgt.process.cmdline contains "chcp" or tgt.process.cmdline contains "chcp " or tgt.process.cmdline contains "chcp  ")))
```


# Original Sigma Rule:
```yaml
title: Console CodePage Lookup Via CHCP
id: 7090adee-82e2-4269-bd59-80691e7c6338
status: test
description: Detects use of chcp to look up the system locale value as part of host discovery
references:
    - https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chcp
author: _pete_0, TheDFIRReport
date: 2022-02-21
modified: 2024-03-05
tags:
    - attack.discovery
    - attack.t1614.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        ParentCommandLine|contains|windash:
            - ' -c '
            - ' -r '
            - ' -k '
        Image|endswith: '\chcp.com'
        CommandLine|endswith:
            - 'chcp'
            - 'chcp '
            - 'chcp  '
    condition: selection
falsepositives:
    - During Anaconda update the 'conda.exe' process will eventually execution the 'chcp' command.
    - Discord was seen using chcp to look up code pages
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_chcp_codepage_lookup/info.yml
```
