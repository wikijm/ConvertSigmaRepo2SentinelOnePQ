```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\curl.exe" or tgt.process.displayName="The curl executable") and ((tgt.process.cmdline contains " --form" or tgt.process.cmdline contains " --upload-file " or tgt.process.cmdline contains " --data " or tgt.process.cmdline contains " --data-") or tgt.process.cmdline matches "\\s-[FTd]\\s")) and (not (tgt.process.cmdline contains "://localhost" or tgt.process.cmdline contains "://127.0.0.1"))))
```


# Original Sigma Rule:
```yaml
title: Potential Data Exfiltration Via Curl.EXE
id: 00bca14a-df4e-4649-9054-3f2aa676bc04
status: test
description: Detects the execution of the "curl" process with "upload" flags. Which might indicate potential data exfiltration
references:
    - https://twitter.com/d1r4c/status/1279042657508081664
    - https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-19---curl-upload-file
    - https://curl.se/docs/manpage.html
author: Florian Roth (Nextron Systems), Cedric MAURUGEON (Update)
date: 2020-07-03
modified: 2023-05-02
tags:
    - attack.exfiltration
    - attack.t1567
    - attack.t1105
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\curl.exe'
        - Product: 'The curl executable'
    selection_cli:
        - CommandLine|contains:
              - ' --form' # Also covers the "--form-string"
              - ' --upload-file '
              - ' --data '
              - ' --data-' # For flags like: "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode"
        - CommandLine|re: '\s-[FTd]\s' # We use regex to ensure a case sensitive argument detection
    filter_optional_localhost:
        CommandLine|contains:
            - '://localhost'
            - '://127.0.0.1'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Scripts created by developers and admins
level: medium
```
