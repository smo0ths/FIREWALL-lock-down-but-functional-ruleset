# LDFRS (PowerShell script) v0.0.0
##### this is for Malwarebytes Windows Firewall Control
## what to do:
##### use [Registry-Tweaks-Refresh](https://github.com/smo0ths/Registry-Tweaks-Refresh.bat) with this
##### and use [My-Network-Adaptor-Settings](https://github.com/smo0ths/My-Network-Adaptor-Settings) with this
##### the (games may need this) 2 rules need testing just enable them if problematic
#### Malwarebytes Windows Firewall Control settings (from main panel):
* ##### Profiles: *medium*
* ##### Notifications: *check display, set close notification to 999, uncheck all but use generic block rules on page*
* ##### Options: *check shell/start*
* ##### Rules: *check outbound/domain/private/public*
* ##### Security: *Check secure profile/rules, delete unauthorized rules, press - on all other authorized groups but WFC and temp rules*
#### Rules Panel: 
* ##### delete rules you didn't make
* ##### Remember to set ALLOW to the [BLOCK IF UPDATES DISABLED] section in Rules Panel if updating and [BLOCK IF NOT USING] for other stuff
## then copy/paste in PowerShell:

```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*'; Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ Allow DHCP In UDP 68 67 (Server response)';Service='Dhcp';Protocol='UDP';LPort=68;RPort=67;Action='Allow';Profile='Domain,Private,Public';Direction='Inbound'},
@{Name='✔️ Allow DHCP Out UDP 68 67 (Client request)';Service='Dhcp';Protocol='UDP';LPort=68;RPort=67;Action='Allow';Profile='Domain,Private,Public';Direction='Outbound'},
@{Name='✔️ Allow DNS Out TCP Any 53 (Fallback)';Service='Dnscache';Protocol='TCP';LPort='*';RPort=53;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS Out UDP Any 53 (Resolution)';Service='Dnscache';Protocol='UDP';LPort='*';RPort=53;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow HTTP Out TCP Any 80 (Web traffic)';Protocol='TCP';LPort='*';RPort=80;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow HTTPS Out TCP Any 443 (Web traffic)';Protocol='TCP';LPort='*';RPort=443;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 In EchoReply (Ping reply)';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 Out EchoRequest (Ping request)';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow svchost Out HTTP TCP Any 80 (General access)';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='*';RPort=80;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow svchost Out HTTPS TCP Any 443 (General access)';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='*';RPort=443;Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ TEMP BLOCK NCSI Probe Dnscache (games may need this)';Service='Dnscache';Protocol='TCP';LPort='*';RPort=443;RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ TEMP BLOCK NCSI Probe svchost.exe (games may need this)';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='*';RPort=443;RAddr='127.0.0.1';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ TEMP BLOCK NCSI Support netprofm (Network List Service)';Service='netprofm';Protocol='TCP';LPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ TEMP BLOCK NCSI Support Wcmsvc (HTTP Probe)';Service='Wcmsvc';Protocol='TCP';LPort='*';RPort=80;Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ TEMP BLOCK W32Time (Time sync)';Service='W32Time';Protocol='UDP';LPort=123;RPort=123;Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Appinfo';Service='Appinfo';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] appmodel';Service='appmodel';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] BDESVC';Service='BDESVC';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] dasHost.exe (manages wired/wireless device pairing)';Program='C:\Windows\System32\dashost.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DcomLaunch';Service='DcomLaunch';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DevicesFlow';Service='DevicesFlow';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DiagTrack (Telemetry Service)';Service='DiagTrack';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Dnscache (mDNS/Local Discovery)';Service='Dnscache';Protocol='UDP';LPort=5353;RPort=5353;Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] EventLog RPC INBOUND';Service='EventLog';Protocol='TCP';LPort=135;Action='Block';Profile='Domain,Private';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] ICMPv6 INBOUND (IPv6 Control Messaging)';Protocol='58';Action='Block';Profile='Any';Direction='Inbound';IcmpType='Any'},
@{Name='✖ [BLOCK IF NOT USING] ICMPv6 OUTBOUND (IPv6 Control Messaging)';Protocol='58';Action='Block';Profile='Any';Direction='Outbound';IcmpType='Any'},
@{Name='✖ [BLOCK IF NOT USING] IGMP INBOUND (Multicast Group Management)';Protocol='2';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP OUTBOUND (Multicast Group Management)';Protocol='2';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IKEEXT';Service='IKEEXT';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Broadcast)';Service='LanmanServer';Protocol='UDP';LPort=138;RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Name)';Service='LanmanServer';Protocol='UDP';LPort=137;RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND (LAN Session)';Service='LanmanServer';Protocol='TCP';LPort=139;RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Service='LanmanServer';Protocol='TCP';LPort=445;RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LocalService';Service='LocalService';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LocalServiceNetworkRestricted';Service='LocalServiceNetworkRestricted';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] NetworkService';Service='NetworkService';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] osprivacy';Service='osprivacy';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Schedule';Service='Schedule';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SENS';Service='SENS';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] ShellHWDetection';Service='ShellHWDetection';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] spoolsv.exe';Program='C:\Windows\System32\spoolsv.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TermService INBOUND';Service='TermService';Protocol='TCP';LPort=3389;RPort='*';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Themes';Service='Themes';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UdkSvcGroup';Service='UdkSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UnistackSvcGroup';Service='UnistackSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UserManager';Service='UserManager';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UserProfileService';Service='UserProfileService';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WerSvc';Service='WerSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Winmgmt';Service='Winmgmt';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WpnService';Service='WpnService';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] AppIdCertStoreCheck.exe';Program='C:\Windows\System32\AppIdCertStoreCheck.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] BITS';Service='BITS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] CompatTelRunner.exe';Program='C:\Windows\System32\CompatTelRunner.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] CryptSvc';Service='CryptSvc';Protocol='TCP';LPort='*';RPort=80;Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DoSvc';Service='DoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] explorer.exe';Program='C:\Windows\explorer.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] lsass.exe';Program='C:\Windows\System32\lsass.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] MoUsoCoreWorker.exe';Program='C:\Windows\System32\MoUsoCoreWorker.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] RPCSS';Service='RPCSS';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] taskhostw.exe';Program='C:\Windows\System32\taskhostw.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] TokenBroker';Service='TokenBroker';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WaaSMedicAgent.exe';Program='C:\Windows\System32\WaaSMedicAgent.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WinHttpAutoProxySvc';Service='WinHttpAutoProxySvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wuauserv';Service='wuauserv';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'}
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
