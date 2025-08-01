```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/mkfifo" and tgt.process.cmdline contains " /tmp/"))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Named Pipe Created Via Mkfifo
id: 999c3b12-0a8c-40b6-8e13-dd7d62b75c7a
related:
    - id: 9d779ce8-5256-4b13-8b6f-b91c602b43f4
      type: derived
status: test
description: Detects the creation of a new named pipe using the "mkfifo" utility in a potentially suspicious location
references:
    - https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk
    - https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-16
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/mkfifo'
        # Note: Add more potentially suspicious locations
        CommandLine|contains: ' /tmp/'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
