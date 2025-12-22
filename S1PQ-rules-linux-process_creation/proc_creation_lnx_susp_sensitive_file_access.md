```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/echo" or tgt.process.image.path contains "/grep" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/tail") and tgt.process.cmdline contains ">") or (tgt.process.image.path contains "/emacs" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/sed" or tgt.process.image.path contains "/vi" or tgt.process.image.path contains "/vim")) and (tgt.process.cmdline contains "/bin/login" or tgt.process.cmdline contains "/bin/passwd" or tgt.process.cmdline contains "/boot/" or tgt.process.cmdline="*/etc/*.conf*" or tgt.process.cmdline contains "/etc/cron." or tgt.process.cmdline contains "/etc/crontab" or tgt.process.cmdline contains "/etc/hosts" or tgt.process.cmdline contains "/etc/init.d" or tgt.process.cmdline contains "/etc/sudoers" or tgt.process.cmdline contains "/opt/bin/" or tgt.process.cmdline contains "/sbin" or tgt.process.cmdline contains "/usr/bin/" or tgt.process.cmdline contains "/usr/local/bin/")))
```


# Original Sigma Rule:
```yaml
title: Potential Suspicious Change To Sensitive/Critical Files
id: 86157017-c2b1-4d4a-8c33-93b8e67e4af4
status: test
description: Detects changes of sensitive and critical files. Monitors files that you don't expect to change without planning on Linux system.
references:
    - https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview#which-files-should-i-monitor
author: '@d4ns4n_ (Wuerth-Phoenix)'
date: 2023-05-30
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_img_1:
        Image|endswith:
            - '/cat'
            - '/echo'
            - '/grep'
            - '/head'
            - '/more'
            - '/tail'
        CommandLine|contains: '>'
    selection_img_2:
        Image|endswith:
            - '/emacs'
            - '/nano'
            - '/sed'
            - '/vi'
            - '/vim'
    selection_paths:
        CommandLine|contains:
            - '/bin/login'
            - '/bin/passwd'
            - '/boot/'
            - '/etc/*.conf'
            - '/etc/cron.' # Covers different cron config files "daily", "hourly", etc.
            - '/etc/crontab'
            - '/etc/hosts'
            - '/etc/init.d'
            - '/etc/sudoers'
            - '/opt/bin/'
            - '/sbin' # Covers: '/opt/sbin', '/usr/local/sbin/', '/usr/sbin/'
            - '/usr/bin/'
            - '/usr/local/bin/'
    condition: 1 of selection_img_* and selection_paths
falsepositives:
    - Some false positives are to be expected on user or administrator machines. Apply additional filters as needed.
level: medium
```
