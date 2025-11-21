# LDFRS (PowerShell script) v0.1.2
##### this is for Malwarebytes Windows Firewall Control
## what to do:
##### use [Registry-Tweaks-Refresh](https://github.com/smo0ths/Registry-Tweaks-Refresh.bat) and [My-Network-Adaptor-Settings](https://github.com/smo0ths/My-Network-Adaptor-Settings) with this
#
#### Malwarebytes Windows Firewall Control settings (from main panel):
* ##### Profiles: *medium*
* ##### Notifications: *check display, set close notification to 999, default advanced notifications settings is fine
* ##### Options: *check shell/start*
* ##### Rules: *check outbound/domain/private/public*
* ##### Security: *check secure profile/secure rules, delete unauthorized rules (press - on all other authorized groups but WFC and temp rules*)
#### Rules Panel: 
* ##### delete rules you didn't make
#
* ##### Remember to set ALLOW to the [BLOCK IF UPDATES DISABLED] [BLOCK IF NOT USING] [BLOCK IF UPDATES/LOGIN DISABLED] if needed
#
## then copy/paste in PowerShell:
#
```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*'; Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ Allow DHCP INBOUND UDP (Server response)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';LAddr='Any';RAddr='Any';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCP OUTBOUND UDP (Client request)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Domain,Private,Public';Direction='Outbound'},
@{Name='✔️ Allow DHCPv6 INBOUND UDP (Server response)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv6 OUTBOUND UDP (Client request)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';RAddr='ff02::1:2';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS OUTBOUND TCP (Fallback)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS OUTBOUND UDP (Resolution)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow HTTP/HTTPS OUTBOUND TCP (Web traffic)';Program='Any';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 INBOUND EchoReply (Ping reply)';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 OUTBOUND EchoRequest (Ping request)';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow ICMPv6 INBOUND (IPv6 Control Messaging)';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='Any'},
@{Name='✔️ Allow ICMPv6 OUTBOUND (IPv6 Control Messaging)';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='Any'},
@{Name='✔️ Allow iphlpsvc (IP Helper)';Program='C:\Windows\System32\svchost.exe';Service='iphlpsvc';Protocol='TCP';LPort='*';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Network Profile Helper (Network List Service/Tray Icon)';Program='C:\Windows\System32\svchost.exe';Service='netprofm';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] AppIdCertStoreCheck.exe';Program='C:\Windows\System32\AppIdCertStoreCheck.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] BDESVC (BitLocker Drive Encryption Service)';Program='C:\Windows\System32\svchost.exe';Service='BDESVC';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CompatTelRunner.exe';Program='C:\Windows\System32\CompatTelRunner.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] dasHost.exe (manages wired/wireless device pairing)';Program='C:\Windows\System32\dashost.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DcomLaunch';Program='C:\Windows\System32\svchost.exe';Service='DcomLaunch';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DevicesFlow';Program='C:\Windows\System32\svchost.exe';Service='DevicesFlow';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DiagTrack (Connected User Experiences and Telemetry)';Program='C:\Windows\System32\svchost.exe';Service='DiagTrack';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Dnscache (mDNS/Local Discovery)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';LPort='*';RPort='5353';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] EventLog RPC INBOUND';Program='C:\Windows\System32\svchost.exe';Service='EventLog';Protocol='TCP';LPort='135';Action='Block';Profile='Domain,Private';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] explorer.exe (Media metadata, Quick Access shares, OneDrive sync, search/index lookups)';Program='C:\Windows\explorer.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP INBOUND (Multicast Group Management)';Program='System';Protocol='2';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP NT Kernel & System OUTBOUND (Multicast Group Management)';Program='System';Protocol='2';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP OUTBOUND (Multicast Group Management)';Program='System';Protocol='2';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Broadcast)';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='UDP';LPort='138';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Name)';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='UDP';LPort='137';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Session)';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='139';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='445';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanWorkstation (SMB Client/File Shares)';Program='C:\Windows\System32\svchost.exe';Service='LanmanWorkstation';Protocol='TCP';LPort='*';RPort=@('445','443');RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Loopback HTTPS Probe (Dnscache)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';LPort='*';RPort='443';RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Loopback HTTPS Probe (svchost)';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='*';RPort='443';RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] mpcmdrun.exe (Microsoft Malware Protection Command Line Utility)';Program='C:\program files\windows defender\mpcmdrun.exe';Protocol='Any';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] OneSyncSvc (Sync Host)';Program='C:\Windows\System32\svchost.exe';Service='OneSyncSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] osprivacy';Program='C:\Windows\System32\svchost.exe';Service='osprivacy';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote (protocol 47) INBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote GRE (protocol 47) OUTBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote L2TP UDP INBOUND';Program='System';Protocol='UDP';LPort='1701';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote L2TP UDP OUTBOUND';Program='System';Protocol='UDP';RPort='1701';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote PPTP TCP INBOUND';Program='System';Protocol='TCP';LPort='1723';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote PPTP TCP OUTBOUND';Program='System';Protocol='TCP';RPort='1723';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='TCP';LPort='3389';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP TCP OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='TCP';RPort='3389';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP UDP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='UDP';LPort='3389';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RPC Dynamic Ports INBOUND';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='49152-65535';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RPC TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='135';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote SMB TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='445';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote WinRM TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='TCP';LPort='5985-5986';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] RPCSS';Program='C:\Windows\System32\svchost.exe';Service='RPCSS';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SENS (System Event Notification Service)';Program='C:\Windows\System32\svchost.exe';Service='SENS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] spoolsv.exe';Program='C:\Windows\System32\spoolsv.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TimeBrokerSvc INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TimeBrokerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound';Enabled='True'},
@{Name='✖ [BLOCK IF NOT USING] UdkSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UdkSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WerSvc (Windows Error Reporting Service)';Program='C:\Windows\System32\svchost.exe';Service='WerSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Appinfo';Program='C:\Windows\System32\svchost.exe';Service='Appinfo';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] appmodel';Program='C:\Windows\System32\svchost.exe';Service='appmodel';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] BITS';Program='C:\Windows\System32\svchost.exe';Service='BITS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] ClipSVC (Client License Service)';Program='C:\Windows\System32\svchost.exe';Service='ClipSVC';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] CryptSvc';Program='C:\Windows\System32\svchost.exe';Service='CryptSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DoSvc (Delivery Optimization)';Program='C:\Windows\System32\svchost.exe';Service='DoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DsmSvc (Device Setup Manager/enable for auto driver downloads)';Program='C:\Windows\System32\svchost.exe';Service='DsmSvc';Protocol='TCP';LPort='*';RPort=@('443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] IKEEXT (IKE and AuthIP IPsec Keying Modules)';Program='C:\Windows\System32\svchost.exe';Service='IKEEXT';Protocol='UDP';LPort='500';RPort='500';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] InstallService (Microsoft Store Install Service)';Program='C:\Windows\System32\svchost.exe';Service='InstallService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] LicenseManager (Windows License Manager Service/Activation/Validation)';Program='C:\Windows\System32\svchost.exe';Service='LicenseManager';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] MoUsoCoreWorker.exe (Part of Update Orchestrator UUS framework)';Program='C:\Windows\UUS\amd64\MoUsoCoreWorker.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] NetworkService (Windows Online Check)';Program='C:\Windows\System32\svchost.exe';Service='NetworkService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] NlaSvc (Network Location Awareness)';Program='C:\Windows\System32\svchost.exe';Service='NlaSvc';Protocol='TCP';LPort='*';RPort=@('443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Schedule (Task Scheduler)';Program='C:\Windows\System32\svchost.exe';Service='Schedule';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] ShellHWDetection';Program='C:\Windows\System32\svchost.exe';Service='ShellHWDetection';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] taskhostw.exe (Windows service host for DLL‑based tasks)';Program='C:\Windows\System32\taskhostw.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Themes';Program='C:\Windows\System32\svchost.exe';Service='Themes';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UnistackSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UnistackSvcGroup';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UserManager';Program='C:\Windows\System32\svchost.exe';Service='UserManager';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UserProfileService';Program='C:\Windows\System32\svchost.exe';Service='UserProfileService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UsoSvc (Update Orchestrator Service)';Program='C:\Windows\System32\svchost.exe';Service='UsoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] VaultSvc';Program='C:\Windows\System32\svchost.exe';Service='VaultSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] W32Time (Time sync)';Program='C:\Windows\System32\svchost.exe';Service='W32Time';Protocol='UDP';LPort='123';RPort='123';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WaaSMedicAgent.exe (Windows Update Medic Service)';Program='C:\Windows\UUS\amd64\WaaSMedicAgent.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Wcmsvc (NCSI HTTP Probe)';Program='C:\Windows\System32\svchost.exe';Service='Wcmsvc';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Winmgmt (Windows Management Instrumentation)';Program='C:\Windows\System32\svchost.exe';Service='Winmgmt';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WpnService (Windows Push Notifications System Service)';Program='C:\Windows\System32\svchost.exe';Service='WpnService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wuauserv (Windows Update)';Program='C:\Windows\System32\svchost.exe';Service='wuauserv';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES/LOGIN DISABLED] lsass.exe (Local Security Authority Subsystem Service)';Program='C:\Windows\System32\lsass.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES/LOGIN DISABLED] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES/LOGIN DISABLED] TokenBroker (Web Account Manager)';Program='C:\Windows\System32\svchost.exe';Service='TokenBroker';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES/LOGIN DISABLED] WinHttpAutoProxySvc';Program='C:\Windows\System32\svchost.exe';Service='WinHttpAutoProxySvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES/LOGIN DISABLED] wlidsvc (Microsoft Account Sign-in Assistant)';Program='C:\Windows\System32\svchost.exe';Service='wlidsvc';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'}
)
$log="$([Environment]::GetFolderPath('Desktop'))\FirewallRules.log"
foreach($r in $rules){
  $p=@{DisplayName=$r.Name;Direction=$r.Direction;Action=$r.Action;Protocol=$r.Protocol;Profile=$r.Profile;Enabled='True';Group='Windows Firewall Control'}
  if($r.Program){$p.Program=$r.Program}
  if($r.Service){$p.Service=$r.Service}
  if($r.Protocol -in 'TCP','UDP'){
    if($r.LPort -ne '*'){$p.LocalPort=$r.LPort}
    if($r.RPort -ne '*'){$p.RemotePort=$r.RPort}
  }
  if($r.LAddr -and $r.LAddr -ne 'Any'){$p.LocalAddress=$r.LAddr -split ','}
  if($r.RAddr -and $r.RAddr -ne 'Any'){
    $tokens=$r.RAddr -split ','
    $valid=$tokens|?{$_ -match '^[\d\.\/:A-Fa-f]+$' -or $_ -in @('LocalSubnet','Internet','Intranet','DNS','Any','DefaultGateway')}
    if($valid.Count){$p.RemoteAddress=$valid}else{"SKIP: $($r.Name)" >> $log; continue}
  }
  try{
    $rule=New-NetFirewallRule @p -EA Stop
    if($r.Enabled -eq 'False'){Set-NetFirewallRule -Name $rule.Name -Enabled False}
    "SUCCESS: $($r.Name)" >> $log
  }
  catch{"FAILED: $($r.Name) $($_.Exception.Message)" >> $log}
}
```
