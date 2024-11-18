```sql
// Translated content (automatically translated on 18-11-2024 01:25:07):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\lazagne.exe" or ((tgt.process.image.path contains ":\PerfLogs\" or tgt.process.image.path contains ":\ProgramData\" or tgt.process.image.path contains ":\Temp\" or tgt.process.image.path contains ":\Tmp\" or tgt.process.image.path contains ":\Windows\Temp\" or tgt.process.image.path contains "\AppData\" or tgt.process.image.path contains "\Downloads\" or tgt.process.image.path contains "\Users\Public\") and (tgt.process.cmdline contains ".exe all" or tgt.process.cmdline contains ".exe browsers" or tgt.process.cmdline contains ".exe chats" or tgt.process.cmdline contains ".exe databases" or tgt.process.cmdline contains ".exe games" or tgt.process.cmdline contains ".exe git" or tgt.process.cmdline contains ".exe mails" or tgt.process.cmdline contains ".exe maven" or tgt.process.cmdline contains ".exe memory" or tgt.process.cmdline contains ".exe multimedia" or tgt.process.cmdline contains ".exe sysadmin" or tgt.process.cmdline contains ".exe unused" or tgt.process.cmdline contains ".exe wifi" or tgt.process.cmdline contains ".exe windows")) or ((tgt.process.cmdline contains "all " or tgt.process.cmdline contains "browsers " or tgt.process.cmdline contains "chats " or tgt.process.cmdline contains "databases " or tgt.process.cmdline contains "games " or tgt.process.cmdline contains "git " or tgt.process.cmdline contains "mails " or tgt.process.cmdline contains "maven " or tgt.process.cmdline contains "memory " or tgt.process.cmdline contains "multimedia " or tgt.process.cmdline contains "php " or tgt.process.cmdline contains "svn " or tgt.process.cmdline contains "sysadmin " or tgt.process.cmdline contains "unused " or tgt.process.cmdline contains "wifi " or tgt.process.cmdline contains "windows ") and (tgt.process.cmdline contains "-oA" or tgt.process.cmdline contains "-oJ" or tgt.process.cmdline contains "-oN" or tgt.process.cmdline contains "-output" or tgt.process.cmdline contains "-password" or tgt.process.cmdline contains "-1Password" or tgt.process.cmdline contains "-apachedirectorystudio" or tgt.process.cmdline contains "-autologon" or tgt.process.cmdline contains "-ChromiumBased" or tgt.process.cmdline contains "-composer" or tgt.process.cmdline contains "-coreftp" or tgt.process.cmdline contains "-credfiles" or tgt.process.cmdline contains "-credman" or tgt.process.cmdline contains "-cyberduck" or tgt.process.cmdline contains "-dbvis" or tgt.process.cmdline contains "-EyeCon" or tgt.process.cmdline contains "-filezilla" or tgt.process.cmdline contains "-filezillaserver" or tgt.process.cmdline contains "-ftpnavigator" or tgt.process.cmdline contains "-galconfusion" or tgt.process.cmdline contains "-gitforwindows" or tgt.process.cmdline contains "-hashdump" or tgt.process.cmdline contains "-iisapppool" or tgt.process.cmdline contains "-IISCentralCertP" or tgt.process.cmdline contains "-kalypsomedia" or tgt.process.cmdline contains "-keepass" or tgt.process.cmdline contains "-keepassconfig" or tgt.process.cmdline contains "-lsa_secrets" or tgt.process.cmdline contains "-mavenrepositories" or tgt.process.cmdline contains "-memory_dump" or tgt.process.cmdline contains "-Mozilla" or tgt.process.cmdline contains "-mRemoteNG" or tgt.process.cmdline contains "-mscache" or tgt.process.cmdline contains "-opensshforwindows" or tgt.process.cmdline contains "-openvpn" or tgt.process.cmdline contains "-outlook" or tgt.process.cmdline contains "-pidgin" or tgt.process.cmdline contains "-postgresql" or tgt.process.cmdline contains "-psi-im" or tgt.process.cmdline contains "-puttycm" or tgt.process.cmdline contains "-pypykatz" or tgt.process.cmdline contains "-Rclone" or tgt.process.cmdline contains "-rdpmanager" or tgt.process.cmdline contains "-robomongo" or tgt.process.cmdline contains "-roguestale" or tgt.process.cmdline contains "-skype" or tgt.process.cmdline contains "-SQLDeveloper" or tgt.process.cmdline contains "-squirrel" or tgt.process.cmdline contains "-tortoise" or tgt.process.cmdline contains "-turba" or tgt.process.cmdline contains "-UCBrowser" or tgt.process.cmdline contains "-unattended" or tgt.process.cmdline contains "-vault" or tgt.process.cmdline contains "-vaultfiles" or tgt.process.cmdline contains "-vnc" or tgt.process.cmdline contains "-windows" or tgt.process.cmdline contains "-winscp" or tgt.process.cmdline contains "-wsl"))))
```


# Original Sigma Rule:
```yaml
title: HackTool - LaZagne Execution
id: c2b86e67-b880-4eec-b045-50bc98ef4844
status: experimental
description: |
    Detects the execution of the LaZagne. A utility used to retrieve multiple types of passwords stored on a local computer.
    LaZagne has been leveraged multiple times by threat actors in order to dump credentials.
references:
    - https://github.com/AlessandroZ/LaZagne/tree/master
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
    - https://cloud.google.com/blog/topics/threat-intelligence/alphv-ransomware-backup/
    - https://securelist.com/defttorero-tactics-techniques-and-procedures/107610/
    - https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/raw/800c0e06571993a54e39571cf27fd474dcc5c0bc/2017/2017.11.14.Muddying_the_Water/muddying-the-water-targeted-attacks.pdf
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-06-24
modified: 2024-08-16
tags:
    - attack.credential-access
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: '\lazagne.exe'
    selection_clionly:
        # Note: This selection can be prone to FP. An initial baseline is required
        Image|contains:
            - ':\PerfLogs\'
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Tmp\'
            - ':\Windows\Temp\'
            - '\AppData\'
            - '\Downloads\'
            - '\Users\Public\'
        CommandLine|endswith:
            - '.exe all'
            - '.exe browsers'
            - '.exe chats'
            - '.exe databases'
            - '.exe games'
            - '.exe git'
            - '.exe mails'
            - '.exe maven'
            - '.exe memory'
            - '.exe multimedia'
            # - '.exe php' # Might be prone to FP
            # - '.exe svn' # Might be prone to FP
            - '.exe sysadmin'
            - '.exe unused'
            - '.exe wifi'
            - '.exe windows'
    selection_cli_modules:
        CommandLine|contains:
            - 'all '
            - 'browsers '
            - 'chats '
            - 'databases '
            - 'games '
            - 'git '
            - 'mails '
            - 'maven '
            - 'memory '
            - 'multimedia '
            - 'php '
            - 'svn '
            - 'sysadmin '
            - 'unused '
            - 'wifi '
            - 'windows '
    selection_cli_options:
        CommandLine|contains:
            - '-oA'
            - '-oJ'
            - '-oN'
            - '-output'
            - '-password'
            - -1Password
            - '-apachedirectorystudio'
            - '-autologon'
            - '-ChromiumBased'
            - '-composer'
            - '-coreftp'
            - '-credfiles'
            - '-credman'
            - '-cyberduck'
            - '-dbvis'
            - '-EyeCon'
            - '-filezilla'
            - '-filezillaserver'
            - '-ftpnavigator'
            - '-galconfusion'
            - '-gitforwindows'
            - '-hashdump'
            - '-iisapppool'
            - '-IISCentralCertP'
            - '-kalypsomedia'
            - '-keepass'
            - '-keepassconfig'
            - '-lsa_secrets'
            - '-mavenrepositories'
            - '-memory_dump'
            - '-Mozilla'
            - '-mRemoteNG'
            - '-mscache'
            - '-opensshforwindows'
            - '-openvpn'
            - '-outlook'
            - '-pidgin'
            - '-postgresql'
            - '-psi-im'
            - '-puttycm'
            - '-pypykatz'
            - '-Rclone'
            - '-rdpmanager'
            - '-robomongo'
            - '-roguestale'
            - '-skype'
            - '-SQLDeveloper'
            - '-squirrel'
            - '-tortoise'
            - '-turba'
            - '-UCBrowser'
            - '-unattended'
            - '-vault'
            - '-vaultfiles'
            - '-vnc'
            - '-windows'
            - '-winscp'
            - '-wsl'
    condition: selection_img or selection_clionly or (selection_cli_modules and selection_cli_options)
falsepositives:
    - Some false positive is expected from tools with similar command line flags.
# Note: Increase the level to "high" after an initial baseline
level: medium
```
