```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\accesschk.exe" or tgt.process.image.path contains "\accesschk64.exe" or tgt.process.image.path contains "\AccessEnum.exe" or tgt.process.image.path contains "\ADExplorer.exe" or tgt.process.image.path contains "\ADExplorer64.exe" or tgt.process.image.path contains "\ADInsight.exe" or tgt.process.image.path contains "\ADInsight64.exe" or tgt.process.image.path contains "\adrestore.exe" or tgt.process.image.path contains "\adrestore64.exe" or tgt.process.image.path contains "\Autologon.exe" or tgt.process.image.path contains "\Autologon64.exe" or tgt.process.image.path contains "\Autoruns.exe" or tgt.process.image.path contains "\Autoruns64.exe" or tgt.process.image.path contains "\autorunsc.exe" or tgt.process.image.path contains "\autorunsc64.exe" or tgt.process.image.path contains "\Bginfo.exe" or tgt.process.image.path contains "\Bginfo64.exe" or tgt.process.image.path contains "\Cacheset.exe" or tgt.process.image.path contains "\Cacheset64.exe" or tgt.process.image.path contains "\Clockres.exe" or tgt.process.image.path contains "\Clockres64.exe" or tgt.process.image.path contains "\Contig.exe" or tgt.process.image.path contains "\Contig64.exe" or tgt.process.image.path contains "\Coreinfo.exe" or tgt.process.image.path contains "\Coreinfo64.exe" or tgt.process.image.path contains "\CPUSTRES.EXE" or tgt.process.image.path contains "\CPUSTRES64.EXE" or tgt.process.image.path contains "\ctrl2cap.exe" or tgt.process.image.path contains "\Dbgview.exe" or tgt.process.image.path contains "\dbgview64.exe" or tgt.process.image.path contains "\Desktops.exe" or tgt.process.image.path contains "\Desktops64.exe" or tgt.process.image.path contains "\disk2vhd.exe" or tgt.process.image.path contains "\disk2vhd64.exe" or tgt.process.image.path contains "\diskext.exe" or tgt.process.image.path contains "\diskext64.exe" or tgt.process.image.path contains "\Diskmon.exe" or tgt.process.image.path contains "\Diskmon64.exe" or tgt.process.image.path contains "\DiskView.exe" or tgt.process.image.path contains "\DiskView64.exe" or tgt.process.image.path contains "\du.exe" or tgt.process.image.path contains "\du64.exe" or tgt.process.image.path contains "\efsdump.exe" or tgt.process.image.path contains "\FindLinks.exe" or tgt.process.image.path contains "\FindLinks64.exe" or tgt.process.image.path contains "\handle.exe" or tgt.process.image.path contains "\handle64.exe" or tgt.process.image.path contains "\hex2dec.exe" or tgt.process.image.path contains "\hex2dec64.exe" or tgt.process.image.path contains "\junction.exe" or tgt.process.image.path contains "\junction64.exe" or tgt.process.image.path contains "\ldmdump.exe" or tgt.process.image.path contains "\listdlls.exe" or tgt.process.image.path contains "\listdlls64.exe" or tgt.process.image.path contains "\livekd.exe" or tgt.process.image.path contains "\livekd64.exe" or tgt.process.image.path contains "\loadOrd.exe" or tgt.process.image.path contains "\loadOrd64.exe" or tgt.process.image.path contains "\loadOrdC.exe" or tgt.process.image.path contains "\loadOrdC64.exe" or tgt.process.image.path contains "\logonsessions.exe" or tgt.process.image.path contains "\logonsessions64.exe" or tgt.process.image.path contains "\movefile.exe" or tgt.process.image.path contains "\movefile64.exe" or tgt.process.image.path contains "\notmyfault.exe" or tgt.process.image.path contains "\notmyfault64.exe" or tgt.process.image.path contains "\notmyfaultc.exe" or tgt.process.image.path contains "\notmyfaultc64.exe" or tgt.process.image.path contains "\ntfsinfo.exe" or tgt.process.image.path contains "\ntfsinfo64.exe" or tgt.process.image.path contains "\pendmoves.exe" or tgt.process.image.path contains "\pendmoves64.exe" or tgt.process.image.path contains "\pipelist.exe" or tgt.process.image.path contains "\pipelist64.exe" or tgt.process.image.path contains "\portmon.exe" or tgt.process.image.path contains "\procdump.exe" or tgt.process.image.path contains "\procdump64.exe" or tgt.process.image.path contains "\procexp.exe" or tgt.process.image.path contains "\procexp64.exe" or tgt.process.image.path contains "\Procmon.exe" or tgt.process.image.path contains "\Procmon64.exe" or tgt.process.image.path contains "\psExec.exe" or tgt.process.image.path contains "\psExec64.exe" or tgt.process.image.path contains "\psfile.exe" or tgt.process.image.path contains "\psfile64.exe" or tgt.process.image.path contains "\psGetsid.exe" or tgt.process.image.path contains "\psGetsid64.exe" or tgt.process.image.path contains "\psInfo.exe" or tgt.process.image.path contains "\psInfo64.exe" or tgt.process.image.path contains "\pskill.exe" or tgt.process.image.path contains "\pskill64.exe" or tgt.process.image.path contains "\pslist.exe" or tgt.process.image.path contains "\pslist64.exe" or tgt.process.image.path contains "\psLoggedon.exe" or tgt.process.image.path contains "\psLoggedon64.exe" or tgt.process.image.path contains "\psloglist.exe" or tgt.process.image.path contains "\psloglist64.exe" or tgt.process.image.path contains "\pspasswd.exe" or tgt.process.image.path contains "\pspasswd64.exe" or tgt.process.image.path contains "\psping.exe" or tgt.process.image.path contains "\psping64.exe" or tgt.process.image.path contains "\psService.exe" or tgt.process.image.path contains "\psService64.exe" or tgt.process.image.path contains "\psshutdown.exe" or tgt.process.image.path contains "\psshutdown64.exe" or tgt.process.image.path contains "\pssuspend.exe" or tgt.process.image.path contains "\pssuspend64.exe" or tgt.process.image.path contains "\RAMMap.exe" or tgt.process.image.path contains "\RDCMan.exe" or tgt.process.image.path contains "\RegDelNull.exe" or tgt.process.image.path contains "\RegDelNull64.exe" or tgt.process.image.path contains "\regjump.exe" or tgt.process.image.path contains "\ru.exe" or tgt.process.image.path contains "\ru64.exe" or tgt.process.image.path contains "\sdelete.exe" or tgt.process.image.path contains "\sdelete64.exe" or tgt.process.image.path contains "\ShareEnum.exe" or tgt.process.image.path contains "\ShareEnum64.exe" or tgt.process.image.path contains "\shellRunas.exe" or tgt.process.image.path contains "\sigcheck.exe" or tgt.process.image.path contains "\sigcheck64.exe" or tgt.process.image.path contains "\streams.exe" or tgt.process.image.path contains "\streams64.exe" or tgt.process.image.path contains "\strings.exe" or tgt.process.image.path contains "\strings64.exe" or tgt.process.image.path contains "\sync.exe" or tgt.process.image.path contains "\sync64.exe" or tgt.process.image.path contains "\Sysmon.exe" or tgt.process.image.path contains "\Sysmon64.exe" or tgt.process.image.path contains "\tcpvcon.exe" or tgt.process.image.path contains "\tcpvcon64.exe" or tgt.process.image.path contains "\tcpview.exe" or tgt.process.image.path contains "\tcpview64.exe" or tgt.process.image.path contains "\Testlimit.exe" or tgt.process.image.path contains "\Testlimit64.exe" or tgt.process.image.path contains "\vmmap.exe" or tgt.process.image.path contains "\vmmap64.exe" or tgt.process.image.path contains "\Volumeid.exe" or tgt.process.image.path contains "\Volumeid64.exe" or tgt.process.image.path contains "\whois.exe" or tgt.process.image.path contains "\whois64.exe" or tgt.process.image.path contains "\Winobj.exe" or tgt.process.image.path contains "\Winobj64.exe" or tgt.process.image.path contains "\ZoomIt.exe" or tgt.process.image.path contains "\ZoomIt64.exe") and (not ((tgt.process.publisher in ("Sysinternals - www.sysinternals.com","Sysinternals")) or not (tgt.process.publisher matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Potential Binary Impersonating Sysinternals Tools
id: 7cce6fc8-a07f-4d84-a53e-96e1879843c9
status: test
description: Detects binaries that use the same name as legitimate sysinternals tools to evade detection
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
author: frack113
date: 2021-12-20
modified: 2022-12-08
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_exe:
        Image|endswith:
            - '\accesschk.exe'
            - '\accesschk64.exe'
            - '\AccessEnum.exe'
            - '\ADExplorer.exe'
            - '\ADExplorer64.exe'
            - '\ADInsight.exe'
            - '\ADInsight64.exe'
            - '\adrestore.exe'
            - '\adrestore64.exe'
            - '\Autologon.exe'
            - '\Autologon64.exe'
            - '\Autoruns.exe'
            - '\Autoruns64.exe'
            - '\autorunsc.exe'
            - '\autorunsc64.exe'
            - '\Bginfo.exe'
            - '\Bginfo64.exe'
            - '\Cacheset.exe'
            - '\Cacheset64.exe'
            - '\Clockres.exe'
            - '\Clockres64.exe'
            - '\Contig.exe'
            - '\Contig64.exe'
            - '\Coreinfo.exe'
            - '\Coreinfo64.exe'
            - '\CPUSTRES.EXE'
            - '\CPUSTRES64.EXE'
            - '\ctrl2cap.exe'
            - '\Dbgview.exe'
            - '\dbgview64.exe'
            - '\Desktops.exe'
            - '\Desktops64.exe'
            - '\disk2vhd.exe'
            - '\disk2vhd64.exe'
            - '\diskext.exe'
            - '\diskext64.exe'
            - '\Diskmon.exe'
            - '\Diskmon64.exe'
            - '\DiskView.exe'
            - '\DiskView64.exe'
            - '\du.exe'
            - '\du64.exe'
            - '\efsdump.exe'
            - '\FindLinks.exe'
            - '\FindLinks64.exe'
            - '\handle.exe'
            - '\handle64.exe'
            - '\hex2dec.exe'
            - '\hex2dec64.exe'
            - '\junction.exe'
            - '\junction64.exe'
            - '\ldmdump.exe'
            - '\listdlls.exe'
            - '\listdlls64.exe'
            - '\livekd.exe'
            - '\livekd64.exe'
            - '\loadOrd.exe'
            - '\loadOrd64.exe'
            - '\loadOrdC.exe'
            - '\loadOrdC64.exe'
            - '\logonsessions.exe'
            - '\logonsessions64.exe'
            - '\movefile.exe'
            - '\movefile64.exe'
            - '\notmyfault.exe'
            - '\notmyfault64.exe'
            - '\notmyfaultc.exe'
            - '\notmyfaultc64.exe'
            - '\ntfsinfo.exe'
            - '\ntfsinfo64.exe'
            - '\pendmoves.exe'
            - '\pendmoves64.exe'
            - '\pipelist.exe'
            - '\pipelist64.exe'
            - '\portmon.exe'
            - '\procdump.exe'
            - '\procdump64.exe'
            - '\procexp.exe'
            - '\procexp64.exe'
            - '\Procmon.exe'
            - '\Procmon64.exe'
            - '\psExec.exe'
            - '\psExec64.exe'
            - '\psfile.exe'
            - '\psfile64.exe'
            - '\psGetsid.exe'
            - '\psGetsid64.exe'
            - '\psInfo.exe'
            - '\psInfo64.exe'
            - '\pskill.exe'
            - '\pskill64.exe'
            - '\pslist.exe'
            - '\pslist64.exe'
            - '\psLoggedon.exe'
            - '\psLoggedon64.exe'
            - '\psloglist.exe'
            - '\psloglist64.exe'
            - '\pspasswd.exe'
            - '\pspasswd64.exe'
            - '\psping.exe'
            - '\psping64.exe'
            - '\psService.exe'
            - '\psService64.exe'
            - '\psshutdown.exe'
            - '\psshutdown64.exe'
            - '\pssuspend.exe'
            - '\pssuspend64.exe'
            - '\RAMMap.exe'
            - '\RDCMan.exe'
            - '\RegDelNull.exe'
            - '\RegDelNull64.exe'
            - '\regjump.exe'
            - '\ru.exe'
            - '\ru64.exe'
            - '\sdelete.exe'
            - '\sdelete64.exe'
            - '\ShareEnum.exe'
            - '\ShareEnum64.exe'
            - '\shellRunas.exe'
            - '\sigcheck.exe'
            - '\sigcheck64.exe'
            - '\streams.exe'
            - '\streams64.exe'
            - '\strings.exe'
            - '\strings64.exe'
            - '\sync.exe'
            - '\sync64.exe'
            - '\Sysmon.exe'
            - '\Sysmon64.exe'
            - '\tcpvcon.exe'
            - '\tcpvcon64.exe'
            - '\tcpview.exe'
            - '\tcpview64.exe'
            - '\Testlimit.exe'
            - '\Testlimit64.exe'
            - '\vmmap.exe'
            - '\vmmap64.exe'
            - '\Volumeid.exe'
            - '\Volumeid64.exe'
            - '\whois.exe'
            - '\whois64.exe'
            - '\Winobj.exe'
            - '\Winobj64.exe'
            - '\ZoomIt.exe'
            - '\ZoomIt64.exe'
    filter_valid:
        Company:
            - 'Sysinternals - www.sysinternals.com'
            - 'Sysinternals'
    filter_empty:
        Company: null
    condition: selection_exe and not 1 of filter*
falsepositives:
    - Unknown
level: medium
```