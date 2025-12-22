```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/lastlog" or tgt.process.cmdline contains "'x:0:'" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/ed" or tgt.process.image.path contains "/head" or tgt.process.image.path contains "/more" or tgt.process.image.path contains "/nano" or tgt.process.image.path contains "/tail" or tgt.process.image.path contains "/vi" or tgt.process.image.path contains "/vim" or tgt.process.image.path contains "/less" or tgt.process.image.path contains "/emacs" or tgt.process.image.path contains "/sqlite3" or tgt.process.image.path contains "/makemap") and (tgt.process.cmdline contains "/etc/passwd" or tgt.process.cmdline contains "/etc/shadow" or tgt.process.cmdline contains "/etc/sudoers" or tgt.process.cmdline contains "/etc/spwd.db" or tgt.process.cmdline contains "/etc/pwd.db" or tgt.process.cmdline contains "/etc/master.passwd")) or tgt.process.image.path contains "/id" or (tgt.process.image.path contains "/lsof" and tgt.process.cmdline contains "-u")))
```


# Original Sigma Rule:
```yaml
title: Local System Accounts Discovery - Linux
id: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
status: test
description: Detects enumeration of local systeam accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
    - https://my.f5.com/manage/s/article/K589
    - https://man.freebsd.org/cgi/man.cgi?pwd_mkdb
author: Alejandro Ortuno, oscd.community, CheraghiMilad
date: 2020-10-08
modified: 2024-12-10
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_1:
        Image|endswith: '/lastlog'
    selection_2:
        CommandLine|contains: '''x:0:'''
    selection_3:
        Image|endswith:
            - '/cat'
            - '/ed'
            - '/head'
            - '/more'
            - '/nano'
            - '/tail'
            - '/vi'
            - '/vim'
            - '/less'
            - '/emacs'
            - '/sqlite3'
            - '/makemap'
        CommandLine|contains:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
            - '/etc/spwd.db'
            - '/etc/pwd.db'
            - '/etc/master.passwd'
    selection_4:
        Image|endswith: '/id'
    selection_5:
        Image|endswith: '/lsof'
        CommandLine|contains: '-u'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: low
```
