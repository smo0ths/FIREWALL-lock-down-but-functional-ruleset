# LDFRS (PowerShell script) v0.0.6
##### this is for Malwarebytes Windows Firewall Control
## what to do:
##### use [Registry-Tweaks-Refresh](https://github.com/smo0ths/Registry-Tweaks-Refresh.bat) and [My-Network-Adaptor-Settings](https://github.com/smo0ths/My-Network-Adaptor-Settings) with this
#
#### Malwarebytes Windows Firewall Control settings (from main panel):
* ##### Profiles: *medium*
* ##### Notifications: *check display, set close notification to 999, uncheck all but use generic block rules on page*
* ##### Options: *check shell/start*
* ##### Rules: *check outbound/domain/private/public*
* ##### Security: *Check secure profile/rules, delete unauthorized rules, press - on all other authorized groups but WFC and temp rules*
#### Rules Panel: 
* ##### delete rules you didn't make
* ##### Remember to set ALLOW to the [BLOCK IF UPDATES DISABLED] section in Rules Panel if updating and check [BLOCK IF NOT USING]
#
## then copy/paste in PowerShell:
#
```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*'; Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ Allow DHCP In UDP 68 67 (Server response)';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Domain,Private,Public';Direction='Inbound'},
@{Name='✔️ Allow DHCP Out UDP 68 67 (Client request)';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Domain,Private,Public';Direction='Outbound'},
@{Name='✔️ Allow DHCPv6 In UDP (Server response)';Service='Dhcp';Program='C:\Windows\System32\svchost.exe';Protocol='UDP';LPort='546';RPort='547';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv6 Out UDP (Client request)';Service='Dhcp';Program='C:\Windows\System32\svchost.exe';Protocol='UDP';LPort='546';RPort='547';RAddr='ff02::1:2';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS Out TCP 53 (Fallback)';Service='Dnscache';Protocol='TCP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS Out UDP 53 (Resolution)';Service='Dnscache';Protocol='UDP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow HTTP/HTTPS(80/443) Out TCP (Web traffic)';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 In EchoReply (Ping reply)';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 Out EchoRequest (Ping request)';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow ICMPv6 INBOUND (IPv6 Control Messaging)';Protocol='58';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='Any'},
@{Name='✔️ Allow ICMPv6 OUTBOUND (IPv6 Control Messaging)';Protocol='58';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='Any'},
@{Name='✔️ Allow iphlpsvc (IP Helper)';Service='iphlpsvc';Protocol='TCP';LPort='*';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Network Profile Helper (Network List Service/Tray Icon)';Service='netprofm';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] AppIdCertStoreCheck.exe';Program='C:\Windows\System32\AppIdCertStoreCheck.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Appinfo';Service='Appinfo';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] appmodel';Service='appmodel';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] BDESVC';Service='BDESVC';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CompatTelRunner.exe';Program='C:\Windows\System32\CompatTelRunner.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CryptSvc';Service='CryptSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] dasHost.exe (manages wired/wireless device pairing)';Program='C:\Windows\System32\dashost.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DcomLaunch';Service='DcomLaunch';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DevicesFlow';Service='DevicesFlow';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DiagTrack (Telemetry Service)';Service='DiagTrack';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Dnscache (mDNS/Local Discovery)';Service='Dnscache';Protocol='UDP';LPort='*';RPort='5353';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DoSvc (Delivery Optimization)';Service='DoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DsmSvc (Device Setup Manager/enable for auto driver downloads)';Service='DsmSvc';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] EventLog RPC INBOUND';Service='EventLog';Protocol='TCP';LPort='135';Action='Block';Profile='Domain,Private';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] explorer.exe';Program='C:\Windows\explorer.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP INBOUND (Multicast Group Management)';Protocol='2';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP OUTBOUND (Multicast Group Management)';Protocol='2';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IKEEXT';Service='IKEEXT';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] InstallService (Microsoft Store Install Service)';Service='InstallService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Broadcast)';Service='LanmanServer';Protocol='UDP';LPort='138';RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Name)';Service='LanmanServer';Protocol='UDP';LPort='137';RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Session)';Service='LanmanServer';Protocol='TCP';LPort='139';RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Service='LanmanServer';Protocol='TCP';LPort='445';RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LocalService';Service='LocalService';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LocalServiceNetworkRestricted';Service='LocalServiceNetworkRestricted';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Loopback HTTPS Probe (Dnscache)';Service='Dnscache';Protocol='TCP';LPort='*';RPort='443';RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Loopback HTTPS Probe (svchost)';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='*';RPort='443';RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] lsass.exe';Program='C:\Windows\System32\lsass.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MoUsoCoreWorker.exe';Program='C:\Windows\UUS\amd64\MoUsoCoreWorker.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] NCSI HTTP Probe (Wcmsvc)';Service='Wcmsvc';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] osprivacy';Service='osprivacy';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] RPCSS';Service='RPCSS';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Schedule';Service='Schedule';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SENS';Service='SENS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] ShellHWDetection';Service='ShellHWDetection';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] spoolsv.exe';Program='C:\Windows\System32\spoolsv.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] taskhostw.exe';Program='C:\Windows\System32\taskhostw.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TermService INBOUND';Service='TermService';Protocol='TCP';LPort='3389';RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Themes';Service='Themes';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TokenBroker';Service='TokenBroker';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UdkSvcGroup';Service='UdkSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UnistackSvcGroup';Service='UnistackSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UserManager';Service='UserManager';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UserProfileService';Service='UserProfileService';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] W32Time (Time sync)';Service='W32Time';Protocol='UDP';LPort='123';RPort='123';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WaaSMedicAgent.exe';Program='C:\Windows\UUS\amd64\WaaSMedicAgent.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WerSvc';Service='WerSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Windows Online Check (NetworkService)';Service='NetworkService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WinHttpAutoProxySvc';Service='WinHttpAutoProxySvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Winmgmt';Service='Winmgmt';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WpnService';Service='WpnService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] BITS';Service='BITS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UsoSvc (Update Orchestrator Service)';Service='UsoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wuauserv';Service='wuauserv';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'}
)
$log="$([Environment]::GetFolderPath('Desktop'))\FirewallRules.log"
foreach($r in $rules){
 $p=@{DisplayName=$r.Name;Direction=$r.Direction;Action=$r.Action;Protocol=$r.Protocol;Profile=$r.Profile;Enabled='True';Group='Windows Firewall Control'}
 if($r.Program){$p.Program=$r.Program}; if($r.Service){$p.Service=$r.Service}
 if($r.Protocol -in 'TCP','UDP'){if($r.LPort -ne '*'){$p.LocalPort=$r.LPort}; if($r.RPort -ne '*'){$p.RemotePort=$r.RPort}}
 if($r.LAddr -and $r.LAddr -ne 'Any'){$p.LocalAddress=$r.LAddr -split ','}
 if($r.RAddr -and $r.RAddr -ne 'Any'){
  $ips=($r.RAddr -split ',') | Where-Object {$_ -match '^[\d\.\/:A-Fa-f]+$'}
  if($ips.Count -gt 0){$p.RemoteAddress=$ips}else{"SKIP: $($r.Name)" >> $log; continue}
 }
 try{$rule=New-NetFirewallRule @p -EA Stop; if($r.Enabled -eq 'False'){Set-NetFirewallRule -Name $rule.Name -Enabled False};"SUCCESS: $($r.Name)" >> $log}
 catch{"FAILED: $($r.Name) $($_.Exception.Message)" >> $log}
}
```
