```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "lsass.dmp" or tgt.process.cmdline contains "lsass.zip" or tgt.process.cmdline contains "lsass.rar" or tgt.process.cmdline contains "Andrew.dmp" or tgt.process.cmdline contains "Coredump.dmp" or tgt.process.cmdline contains "NotLSASS.zip" or tgt.process.cmdline contains "lsass_2" or tgt.process.cmdline contains "lsassdump" or tgt.process.cmdline contains "lsassdmp") or (tgt.process.cmdline contains "lsass" and tgt.process.cmdline contains ".dmp") or (tgt.process.cmdline contains "SQLDmpr" and tgt.process.cmdline contains ".mdmp") or (tgt.process.cmdline contains "nanodump" and tgt.process.cmdline contains ".dmp")))
```


# Original Sigma Rule:
```yaml
title: LSASS Dump Keyword In CommandLine
id: ffa6861c-4461-4f59-8a41-578c39f3f23e
related:
    - id: a5a2d357-1ab8-4675-a967-ef9990a59391
      type: derived
status: test
description: |
    Detects the presence of the keywords "lsass" and ".dmp" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.
references:
    - https://github.com/Hackndo/lsassy
    - https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf
    - https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/credential_access_lsass_memdump_file_created.toml
    - https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/
    - https://github.com/helpsystems/nanodump
    - https://github.com/CCob/MirrorDump
author: E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-24
modified: 2023-08-29
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains:
              - 'lsass.dmp'
              - 'lsass.zip'
              - 'lsass.rar'
              - 'Andrew.dmp'
              - 'Coredump.dmp'
              - 'NotLSASS.zip'  # https://github.com/CCob/MirrorDump
              - 'lsass_2'  # default format of procdump v9.0 is lsass_YYMMDD_HHmmss.dmp
              - 'lsassdump'
              - 'lsassdmp'
        - CommandLine|contains|all:
              - 'lsass'
              - '.dmp'
        - CommandLine|contains|all:
              - 'SQLDmpr'
              - '.mdmp'
        - CommandLine|contains|all:
              - 'nanodump'
              - '.dmp'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
