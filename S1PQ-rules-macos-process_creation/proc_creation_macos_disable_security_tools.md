```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (((tgt.process.image.path="/bin/launchctl" and tgt.process.cmdline contains "unload") and (tgt.process.cmdline contains "com.objective-see.lulu.plist" or tgt.process.cmdline contains "com.objective-see.blockblock.plist" or tgt.process.cmdline contains "com.google.santad.plist" or tgt.process.cmdline contains "com.carbonblack.defense.daemon.plist" or tgt.process.cmdline contains "com.carbonblack.daemon.plist" or tgt.process.cmdline contains "at.obdev.littlesnitchd.plist" or tgt.process.cmdline contains "com.tenablesecurity.nessusagent.plist" or tgt.process.cmdline contains "com.opendns.osx.RoamingClientConfigUpdater.plist" or tgt.process.cmdline contains "com.crowdstrike.falcond.plist" or tgt.process.cmdline contains "com.crowdstrike.userdaemon.plist" or tgt.process.cmdline contains "osquery" or tgt.process.cmdline contains "filebeat" or tgt.process.cmdline contains "auditbeat" or tgt.process.cmdline contains "packetbeat" or tgt.process.cmdline contains "td-agent")) or (tgt.process.image.path="/usr/sbin/spctl" and tgt.process.cmdline contains "disable")))
```


# Original Sigma Rule:
```yaml
title: Disable Security Tools
id: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
status: test
description: Detects disabling security tools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: macos
detection:
    launchctl_unload:
        Image: '/bin/launchctl'
        CommandLine|contains: 'unload'
    security_plists:
        CommandLine|contains:
            - 'com.objective-see.lulu.plist'                     # Objective-See firewall management utility
            - 'com.objective-see.blockblock.plist'               # Objective-See persistence locations watcher/blocker
            - 'com.google.santad.plist'                          # google santa
            - 'com.carbonblack.defense.daemon.plist'             # carbon black
            - 'com.carbonblack.daemon.plist'                     # carbon black
            - 'at.obdev.littlesnitchd.plist'                     # Objective Development Software firewall management utility
            - 'com.tenablesecurity.nessusagent.plist'            # Tenable Nessus
            - 'com.opendns.osx.RoamingClientConfigUpdater.plist' # OpenDNS Umbrella
            - 'com.crowdstrike.falcond.plist'                    # Crowdstrike Falcon
            - 'com.crowdstrike.userdaemon.plist'                 # Crowdstrike Falcon
            - 'osquery'                                          # facebook osquery
            - 'filebeat'                                         # elastic log file shipper
            - 'auditbeat'                                        # elastic auditing agent/log shipper
            - 'packetbeat'                                       # elastic network logger/shipper
            - 'td-agent'                                         # fluentd log shipper
    disable_gatekeeper:
        Image: '/usr/sbin/spctl'
        CommandLine|contains: 'disable'
    condition: (launchctl_unload and security_plists) or disable_gatekeeper
falsepositives:
    - Legitimate activities
level: medium
```
