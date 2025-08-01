```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " /INJECTRUNNING " and (not src.process.image.path="C:\Windows\System32\AppVClient.exe")))
```


# Original Sigma Rule:
```yaml
title: Mavinject Inject DLL Into Running Process
id: 4f73421b-5a0b-4bbf-a892-5a7fb99bea66
related:
    - id: 17eb8e57-9983-420d-ad8a-2c4976c22eb8
      type: obsolete
status: test
description: Detects process injection using the signed Windows tool "Mavinject" via the "INJECTRUNNING" flag
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.004/T1056.004.md
    - https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e
    - https://twitter.com/gN3mes1s/status/941315826107510784
    - https://reaqta.com/2017/12/mavinject-microsoft-injector/
    - https://twitter.com/Hexacorn/status/776122138063409152  # Deleted tweet
    - https://github.com/SigmaHQ/sigma/issues/3742
    - https://github.com/keyboardcrunch/SentinelOne-ATTACK-Queries/blob/6a228d23eefe963ca81f2d52f94b815f61ef5ee0/Tactics/DefenseEvasion.md#t1055-process-injection
author: frack113, Florian Roth
date: 2021-07-12
modified: 2022-12-05
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1055.001
    - attack.t1218.013
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' /INJECTRUNNING '
    filter:
        ParentImage: 'C:\Windows\System32\AppVClient.exe' # This parent is the expected process to launch "mavinject"
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
