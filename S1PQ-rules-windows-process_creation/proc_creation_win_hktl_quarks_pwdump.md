```sql
// Translated content (automatically translated on 06-09-2025 01:50:31):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\QuarksPwDump.exe" or (tgt.process.cmdline in (" -dhl"," --dump-hash-local"," -dhdc"," --dump-hash-domain-cached"," --dump-bitlocker"," -dhd "," --dump-hash-domain ","--ntds-file"))))
```


# Original Sigma Rule:
```yaml
title: HackTool - Quarks PwDump Execution
id: 0685b176-c816-4837-8e7b-1216f346636b
status: test
description: Detects usage of the Quarks PwDump tool via commandline arguments
references:
    - https://github.com/quarkslab/quarkspwdump
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/seedworm-apt-iran-middle-east
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2023-02-05
tags:
    - attack.credential-access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\QuarksPwDump.exe'
    selection_cli:
        CommandLine:
            - ' -dhl'
            - ' --dump-hash-local'
            - ' -dhdc'
            - ' --dump-hash-domain-cached'
            - ' --dump-bitlocker'
            - ' -dhd '
            - ' --dump-hash-domain '
            - '--ntds-file'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
