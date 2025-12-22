```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((src.process.image.path contains "/package_script_service" or src.process.image.path contains "/installer") and (tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/python" or tgt.process.image.path contains "/ruby" or tgt.process.image.path contains "/perl" or tgt.process.image.path contains "/php" or tgt.process.image.path contains "/javascript" or tgt.process.image.path contains "/osascript" or tgt.process.image.path contains "/tclsh" or tgt.process.image.path contains "/curl" or tgt.process.image.path contains "/wget") and (tgt.process.cmdline contains "preinstall" or tgt.process.cmdline contains "postinstall")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Installer Package Child Process
id: e0cfaecd-602d-41af-988d-f6ccebb2af26
status: test
description: Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters
references:
    - https://redcanary.com/blog/clipping-silver-sparrows-wings/
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_installer_package_spawned_network_event.toml
author: Sohan G (D4rkCiph3r)
date: 2023-02-18
tags:
    - attack.t1059
    - attack.t1059.007
    - attack.t1071
    - attack.t1071.001
    - attack.execution
    - attack.command-and-control
logsource:
    category: process_creation
    product: macos
detection:
    selection_installer:
        ParentImage|endswith:
            - '/package_script_service'
            - '/installer'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/python'
            - '/ruby'
            - '/perl'
            - '/php'
            - '/javascript'
            - '/osascript'
            - '/tclsh'
            - '/curl'
            - '/wget'
        CommandLine|contains:
            - 'preinstall'
            - 'postinstall'
    condition: selection_installer
falsepositives:
    - Legitimate software uses the scripts (preinstall, postinstall)
level: medium
```
