```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((src.process.image.path contains "/rsync" or src.process.image.path contains "/rsyncd") and (tgt.process.image.path contains "/ash" or tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/csh" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/ksh" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/tcsh" or tgt.process.image.path contains "/zsh")) and (not tgt.process.cmdline contains " -e ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Invocation of Shell via Rsync
id: 297241f3-8108-4b3a-8c15-2dda9f844594
status: experimental
description: |
    Detects the execution of a shell as sub process of "rsync" without the expected command line flag "-e" being used, which could be an indication of exploitation as described in CVE-2024-12084. This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation.
references:
    - https://sysdig.com/blog/detecting-and-mitigating-cve-2024-12084-rsync-remote-code-execution/
    - https://gist.github.com/Neo23x0/a20436375a1e26524931dd8ea1a3af10
author: Florian Roth
date: 2025-01-18
tags:
    - attack.execution
    - attack.t1059
    - attack.t1203
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/rsync'
            - '/rsyncd'
        Image|endswith:
            - '/ash'
            - '/bash'
            - '/csh'
            - '/dash'
            - '/ksh'
            - '/sh'
            - '/tcsh'
            - '/zsh'
    filter_main_expected:
        CommandLine|contains: ' -e '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
