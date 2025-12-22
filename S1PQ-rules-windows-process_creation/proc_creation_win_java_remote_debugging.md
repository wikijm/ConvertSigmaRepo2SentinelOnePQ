```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "transport=dt_socket,address=" and (tgt.process.cmdline contains "jre1." or tgt.process.cmdline contains "jdk1.")) and (not (tgt.process.cmdline contains "address=127.0.0.1" or tgt.process.cmdline contains "address=localhost"))))
```


# Original Sigma Rule:
```yaml
title: Java Running with Remote Debugging
id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
status: test
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
references:
    - https://dzone.com/articles/remote-debugging-java-applications-with-jdwp
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2023-02-01
tags:
    - attack.t1203
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_jdwp_transport:
        CommandLine|contains: 'transport=dt_socket,address='
    selection_old_jvm_version:
        CommandLine|contains:
            - 'jre1.'
            - 'jdk1.'
    exclusion:
        CommandLine|contains:
            - 'address=127.0.0.1'
            - 'address=localhost'
    condition: all of selection_* and not exclusion
falsepositives:
    - Unknown
level: medium
```
