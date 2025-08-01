```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and (((src.process.image.path contains "com.apple.WebKit.WebContent" or src.process.image.path contains "firefox" or src.process.image.path contains "Google Chrome Helper" or src.process.image.path contains "Google Chrome" or src.process.image.path contains "Microsoft Edge" or src.process.image.path contains "Opera" or src.process.image.path contains "Safari" or src.process.image.path contains "Tor Browser") and (tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/curl" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/ksh" or tgt.process.image.path contains "/osascript" or tgt.process.image.path contains "/perl" or tgt.process.image.path contains "/php" or tgt.process.image.path contains "/pwsh" or tgt.process.image.path contains "/python" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/tcsh" or tgt.process.image.path contains "/wget" or tgt.process.image.path contains "/zsh")) and (not (tgt.process.cmdline contains "--defaults-torrc" or tgt.process.cmdline="*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*" or ((src.process.image.path contains "Google Chrome Helper" or src.process.image.path contains "Google Chrome") and (tgt.process.cmdline="*/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh*" or tgt.process.cmdline="*/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_preflight.sh*" or tgt.process.cmdline="*/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_postflight.sh*")) or (src.process.image.path contains "Microsoft Edge" and (tgt.process.cmdline contains "IOPlatformExpertDevice" or tgt.process.cmdline contains "hw.model")) or ((src.process.image.path contains "Google Chrome Helper" or src.process.image.path contains "Google Chrome") and (tgt.process.cmdline contains "/Users/" and tgt.process.cmdline contains "/Library/Application Support/Google/Chrome/recovery/" and tgt.process.cmdline contains "/ChromeRecovery")))) and (not (not (tgt.process.cmdline matches "\.*") or tgt.process.cmdline=""))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Browser Child Process - MacOS
id: 0250638a-2b28-4541-86fc-ea4c558fa0c6
status: test
description: Detects suspicious child processes spawned from browsers. This could be a result of a potential web browser exploitation.
references:
    - https://fr.slideshare.net/codeblue_jp/cb19-recent-apt-attack-on-crypto-exchange-employees-by-heungsoo-kang
    - https://github.com/elastic/detection-rules/blob/4312d8c9583be524578a14fe6295c3370b9a9307/rules/macos/execution_initial_access_suspicious_browser_childproc.toml
author: Sohan G (D4rkCiph3r)
date: 2023-04-05
tags:
    - attack.initial-access
    - attack.execution
    - attack.t1189
    - attack.t1203
    - attack.t1059
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        ParentImage|contains:
            - 'com.apple.WebKit.WebContent'
            - 'firefox'
            - 'Google Chrome Helper'
            - 'Google Chrome'
            - 'Microsoft Edge'
            - 'Opera'
            - 'Safari'
            - 'Tor Browser'
        Image|endswith:
            - '/bash'
            - '/curl'
            - '/dash'
            - '/ksh'
            - '/osascript'
            - '/perl'
            - '/php'
            - '/pwsh'
            - '/python'
            - '/sh'
            - '/tcsh'
            - '/wget'
            - '/zsh'
    filter_main_generic:
        CommandLine|contains: '--defaults-torrc' # Informs tor to use default config file
    filter_main_ms_autoupdate:
        CommandLine|contains: '/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate' # Microsoft AutoUpdate utility
    filter_main_chrome:
        ParentImage|contains:
            - 'Google Chrome Helper'
            - 'Google Chrome'
        CommandLine|contains:
            - '/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh' # Install the Google Chrome browser
            - '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_preflight.sh' # Updates the Google Chrome branding configuration files
            - '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/*/Resources/keystone_promote_postflight.sh' # Script that performs the post-installation tasks
    filter_main_ms_edge:
        ParentImage|contains: 'Microsoft Edge'
        CommandLine|contains:
            - 'IOPlatformExpertDevice' # Retrieves the IOPlatformUUID (parent process - Microsoft Edge)
            - 'hw.model' # Retrieves model name of the computer's hardware (parent process - Microsoft Edge)
    filter_main_chromerecovery:
        ParentImage|contains:
            - 'Google Chrome Helper'
            - 'Google Chrome'
        CommandLine|contains|all:
            - '/Users/'
            - '/Library/Application Support/Google/Chrome/recovery/'
            - '/ChromeRecovery'
    filter_optional_null:
        # Aoids alerting for the events which do not have command-line arguments
        CommandLine: null
    filter_optional_empty:
        # Aoids alerting for the events which do not have command-line arguments
        CommandLine: ''
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate browser install, update and recovery scripts
level: medium
```
