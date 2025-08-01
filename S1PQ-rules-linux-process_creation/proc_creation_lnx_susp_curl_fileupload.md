```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/curl" and ((tgt.process.cmdline contains " --form" or tgt.process.cmdline contains " --upload-file " or tgt.process.cmdline contains " --data " or tgt.process.cmdline contains " --data-") or tgt.process.cmdline matches "\\s-[FTd]\\s")) and (not (tgt.process.cmdline contains "://localhost" or tgt.process.cmdline contains "://127.0.0.1"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Curl File Upload - Linux
id: 00b90cc1-17ec-402c-96ad-3a8117d7a582
related:
    - id: 00bca14a-df4e-4649-9054-3f2aa676bc04
      type: derived
status: test
description: Detects a suspicious curl process start the adds a file to a web request
references:
    - https://twitter.com/d1r4c/status/1279042657508081664
    - https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-19---curl-upload-file
    - https://curl.se/docs/manpage.html
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems), Cedric MAURUGEON (Update)
date: 2022-09-15
modified: 2023-05-02
tags:
    - attack.exfiltration
    - attack.command-and-control
    - attack.t1567
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/curl'
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
