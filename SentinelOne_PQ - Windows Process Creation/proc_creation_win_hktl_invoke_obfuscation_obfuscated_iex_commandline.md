```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline matches "\\$PSHome\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$PSHome\\[" or tgt.process.cmdline matches "\\$ShellId\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$ShellId\\[" or tgt.process.cmdline matches "\\$env:Public\\[\\s*\\d{1,3}\\s*\\]\\s*\\+\\s*\\$env:Public\\[" or tgt.process.cmdline matches "\\$env:ComSpec\\[(\\s*\\d{1,3}\\s*,){2}" or tgt.process.cmdline matches "\\*mdr\\*\\W\\s*\\)\\.Name" or tgt.process.cmdline matches "\\$VerbosePreference\\.ToString\\(" or tgt.process.cmdline matches "\\[String\\]\\s*\\$VerbosePreference"))
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation Obfuscated IEX Invocation
id: 4bf943c6-5146-4273-98dd-e958fd1e3abf
status: test
description: Detects all variations of obfuscated powershell IEX invocation code generated by Invoke-Obfuscation framework from the following code block
references:
    - https://github.com/danielbohannon/Invoke-Obfuscation/blob/f20e7f843edd0a3a7716736e9eddfa423395dd26/Out-ObfuscatedStringCommand.ps1#L873-L888
author: 'Daniel Bohannon (@Mandiant/@FireEye), oscd.community'
date: 2019-11-08
modified: 2022-12-31
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|re: '\$PSHome\[\s*\d{1,3}\s*\]\s*\+\s*\$PSHome\['
        - CommandLine|re: '\$ShellId\[\s*\d{1,3}\s*\]\s*\+\s*\$ShellId\['
        - CommandLine|re: '\$env:Public\[\s*\d{1,3}\s*\]\s*\+\s*\$env:Public\['
        - CommandLine|re: '\$env:ComSpec\[(\s*\d{1,3}\s*,){2}'
        - CommandLine|re: '\*mdr\*\W\s*\)\.Name'
        - CommandLine|re: '\$VerbosePreference\.ToString\('
        - CommandLine|re: '\[String\]\s*\$VerbosePreference'
    condition: selection
falsepositives:
    - Unknown
level: high
```