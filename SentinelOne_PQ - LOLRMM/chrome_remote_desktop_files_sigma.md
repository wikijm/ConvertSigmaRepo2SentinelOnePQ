```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Google\\Chrome Remote Desktop\*\\remoting_host.exe" or tgt.file.path contains "/Library/PrivilegedHelperTools/ChromeRemoteDesktopHost.app/Contents/MacOS/remoting_me2me_host" or tgt.file.path contains "/Library/PrivilegedHelperTools/ChromeRemoteDesktopHost.app/Contents/MacOS/remoting_me2me_host_service" or tgt.file.path contains "/Library/LaunchAgents/org.chromium.chromoting.plist" or tgt.file.path contains "/Library/LaunchDaemons/org.chromium.chromoting.broker.plist" or tgt.file.path contains "/Library/PrivilegedHelperTools/org.chromium.chromoting.json" or tgt.file.path contains "/Library/PrivilegedHelperTools/org.chromium.chromoting.settings.json" or tgt.file.path contains "/Applications/Chrome Remote Desktop Host Uninstaller.app" or tgt.file.path contains "/opt/google/chrome-remote-desktop/chrome-remote-desktop-host" or tgt.file.path contains "/opt/google/chrome-remote-desktop/chrome-remote-desktop" or tgt.file.path contains "/lib/systemd/system/chrome-remote-desktop.service"))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool File Activity
id: c3595792-bb90-5eb3-88d3-1a6979e87243
status: experimental
description: |
    Detects potential files activity of Chrome Remote Desktop RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files (x86)\Google\Chrome Remote Desktop\*\remoting_host.exe'
            - '/Library/PrivilegedHelperTools/ChromeRemoteDesktopHost.app/Contents/MacOS/remoting_me2me_host'
            - '/Library/PrivilegedHelperTools/ChromeRemoteDesktopHost.app/Contents/MacOS/remoting_me2me_host_service'
            - '/Library/LaunchAgents/org.chromium.chromoting.plist'
            - '/Library/LaunchDaemons/org.chromium.chromoting.broker.plist'
            - '/Library/PrivilegedHelperTools/org.chromium.chromoting.json'
            - '/Library/PrivilegedHelperTools/org.chromium.chromoting.settings.json'
            - '/Applications/Chrome Remote Desktop Host Uninstaller.app'
            - '/opt/google/chrome-remote-desktop/chrome-remote-desktop-host'
            - '/opt/google/chrome-remote-desktop/chrome-remote-desktop'
            - '/lib/systemd/system/chrome-remote-desktop.service'
    condition: selection
falsepositives:
    - Legitimate use of Chrome Remote Desktop
level: medium
```
