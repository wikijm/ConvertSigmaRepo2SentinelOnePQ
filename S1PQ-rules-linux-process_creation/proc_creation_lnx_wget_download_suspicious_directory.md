```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/wget" and (tgt.process.cmdline matches "\\s-O\\s" or tgt.process.cmdline contains "--output-document") and tgt.process.cmdline contains "/tmp/"))
```


# Original Sigma Rule:
```yaml
title: Download File To Potentially Suspicious Directory Via Wget
id: cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
status: test
description: Detects the use of wget to download content to a suspicious directory
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/wget'
    selection_output:
        - CommandLine|re: '\s-O\s' # We use regex to ensure a case sensitive argument detection
        - CommandLine|contains: '--output-document'
    selection_path:
        CommandLine|contains: '/tmp/'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
