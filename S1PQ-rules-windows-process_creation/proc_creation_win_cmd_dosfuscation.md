```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "^^" or tgt.process.cmdline contains "^|^" or tgt.process.cmdline contains ",;," or tgt.process.cmdline contains ";;;;" or tgt.process.cmdline contains ";; ;;" or tgt.process.cmdline contains "(,(," or tgt.process.cmdline contains "%COMSPEC:~" or tgt.process.cmdline contains " c^m^d" or tgt.process.cmdline contains "^c^m^d" or tgt.process.cmdline contains " c^md" or tgt.process.cmdline contains " cm^d" or tgt.process.cmdline contains "^cm^d" or tgt.process.cmdline contains " s^et " or tgt.process.cmdline contains " s^e^t " or tgt.process.cmdline contains " se^t "))
```


# Original Sigma Rule:
```yaml
title: Potential Dosfuscation Activity
id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: test
description: Detects possible payload obfuscation via the commandline
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
    - https://github.com/danielbohannon/Invoke-DOSfuscation
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-02-15
modified: 2023-03-06
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '^^'
            - '^|^'
            - ',;,'
            - ';;;;'
            - ';; ;;'
            - '(,(,'
            - '%COMSPEC:~'
            - ' c^m^d'
            - '^c^m^d'
            - ' c^md'
            - ' cm^d'
            - '^cm^d'
            - ' s^et '
            - ' s^e^t '
            - ' se^t '
            # - '%%'
            # - '&&'
            # - '""'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
