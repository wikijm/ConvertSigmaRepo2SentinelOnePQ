```sql
// Translated content (automatically translated on 09-09-2026 02:56:53):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/dscl" and (tgt.process.cmdline contains "list" and tgt.process.cmdline contains "/users")) or (tgt.process.image.path contains "/dscacheutil" and (tgt.process.cmdline contains "-q" and tgt.process.cmdline contains "user")) or tgt.process.cmdline="*'*:0:'*" or ((tgt.process.image.path contains "/cat" or tgt.process.image.path contains "/awk" or tgt.process.image.path contains "/grep") and (tgt.process.cmdline contains "/etc/passwd" or tgt.process.cmdline contains "/etc/sudoers")) or tgt.process.image.path contains "/id" or (tgt.process.image.path contains "/lsof" and tgt.process.cmdline contains "-u") or (tgt.process.image.path contains "/who" or tgt.process.image.path contains "/w" or tgt.process.image.path contains "/users" or tgt.process.image.path contains "/last") or (tgt.process.image.path contains "/ls" and (tgt.process.cmdline contains "/Users" or tgt.process.cmdline contains "/Users'" or tgt.process.cmdline contains "/Users\"")) or ((tgt.process.image.path contains "/defaults" or tgt.process.image.path contains "/plutil") and tgt.process.cmdline contains "com.apple.loginwindow")))
```


# Original Sigma Rule:
```yaml
title: Local System Accounts Discovery - MacOs
id: ddf36b67-e872-4507-ab2e-46bda21b842c
status: test
description: |
    Detects enumeration of local system accounts on MacOS systems.
    This can be used by attackers to identify accounts for lateral movement or privilege escalation.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
    - https://ss64.com/osx/dscl.html
    - https://ss64.com/mac/dscacheutil.html
author: Alejandro Ortuno, oscd.community
date: 2020-10-08
modified: 2026-07-07
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: macos
detection:
    selection_dscl:
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - 'list'
            - '/users'
    selection_dscacheutil:
        Image|endswith: '/dscacheutil'
        CommandLine|contains|all:
            - '-q'
            - 'user'
    selection_root:
        CommandLine|contains: '''*:0:'''
    selection_passwd_sudo:
        Image|endswith:
            - '/cat'
            - '/awk'
            - '/grep'
        CommandLine|contains:
            - '/etc/passwd'
            - '/etc/sudoers'
    selection_id:
        Image|endswith: '/id'
    selection_lsof:
        Image|endswith: '/lsof'
        CommandLine|contains: '-u'
    selection_logged_in_users:
        Image|endswith:
            - '/who'
            - '/w'
            - '/users'
            - '/last'
    selection_home_dir_listing:
        Image|endswith: '/ls'
        CommandLine|endswith:
            - '/Users'
            - "/Users'"
            - '/Users"'
    selection_loginwindow_prefs:
        Image|endswith:
            - '/defaults' # defaults read /Library/Preferences/com.apple.loginwindow
            - '/plutil' # plutil -p /Library/Preferences/com.apple.loginwindow.plist
        CommandLine|contains: 'com.apple.loginwindow'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: low
```
