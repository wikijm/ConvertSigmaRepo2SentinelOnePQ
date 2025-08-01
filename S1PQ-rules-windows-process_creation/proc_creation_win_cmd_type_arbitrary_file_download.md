```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "type " and tgt.process.cmdline contains " > \\") or (tgt.process.cmdline contains "type \\" and tgt.process.cmdline contains " > ")))
```


# Original Sigma Rule:
```yaml
title: Potential Download/Upload Activity Using Type Command
id: aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f
status: test
description: Detects usage of the "type" command to download/upload data from WebDAV server
references:
    - https://mr0range.com/a-new-lolbin-using-the-windows-type-command-to-upload-download-files-81d7b6179e22
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-14
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    # Note that since built in CMD commands do not trigger a process creation. This would be detected only if used in a "/c" command
    selection_upload:
        CommandLine|contains|all:
            - 'type '
            - ' > \\\\'
    selection_download:
        CommandLine|contains|all:
            - 'type \\\\'
            - ' > ' # Space are added to increase atom length and speed up matching. If your backend can handle this remove the space
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
