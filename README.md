# LDFRS (PowerShell script) v0.2.7
##### this is for Malwarebytes Windows Firewall Control
## what to do:
##### use [Registry-Tweaks-Refresh](https://github.com/smo0ths/Registry-Tweaks-Refresh.bat) and [My-Network-Adaptor-Settings](https://github.com/smo0ths/My-Network-Adaptor-Settings) with this
#
#### Malwarebytes Windows Firewall Control settings (from main panel):
* ##### Profiles: *medium*
* ##### Notifications: *check display, set close notification to 999, default advanced notifications settings is fine
* ##### Options: *check shell/start*
* ##### Rules: *check outbound/domain/private/public*
* ##### Security: *check secure profile/secure rules(w/ disable unauthorized rules) and delete unauthorized groups though (press - on all other authorized groups keep WFC and temp rules)*
#
* ##### Rules Panel: *open delete/block rules you don't want*
* ##### *change disabled rules group name Windows Firewall Control and enable if you want to keep rule*
* ##### *set ALLOW to the [BLOCK IF UPDATES DISABLED] and [BLOCK IF NOT USING] if needed*
* ##### *Enable-Block Web traffic HTTP OUTBOUND TCP (unencrypted) if you want to block all HTTP traffic*
* ##### *right click block apps before opening them*
* ##### *when pop-up click customize this rule before creating it > uncheck local ports/remote IP > and then allow/block
#
## copy/paste in PowerShell:
#
```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*';
Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ Allow CryptSvc (Certificate validation/Signature checks)';Program='C:\Windows\System32\svchost.exe';Service='CryptSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DHCPv4 INBOUND (Server Response)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv4 OUTBOUND (Client Request)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DHCPv6 INBOUND (Server Response)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv6 OUTBOUND (Client Request)';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';RAddr='ff02::1:2';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS OUTBOUND TCP (Fallback)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS OUTBOUND UDP (Resolution)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';LPort='*';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 INBOUND (Ping reply)';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 OUTBOUND (Ping request)';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow ICMPv6 INBOUND (Ping reply)';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='129'},
@{Name='✔️ Allow ICMPv6 OUTBOUND (Ping request)';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='128'},
@{Name='✔️ Allow iphlpsvc';Program='C:\Windows\System32\svchost.exe';Service='iphlpsvc';Protocol='TCP';LPort='*';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow netprofm';Program='C:\Windows\System32\svchost.exe';Service='netprofm';Protocol='TCP';LPort='*';RPort='80';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Web traffic HTTPS OUTBOUND TCP (encrypted)';Program='Any';Protocol='TCP';LPort='*';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Web traffic QUIC HTTP3 OUTBOUND UDP (encrypted)';Program='Any';Protocol='UDP';LPort='*';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Disable/Enable Block Web traffic HTTP OUTBOUND TCP (unencrypted)';Program='Any';Protocol='TCP';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound';Enabled='False'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Appinfo';Program='C:\Windows\System32\svchost.exe';Service='Appinfo';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] appmodel';Program='C:\Windows\System32\svchost.exe';Service='appmodel';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] AppXSvc (WSAPPX)';Program='C:\Windows\System32\svchost.exe';Service='AppXSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] BITS';Program='C:\Windows\System32\svchost.exe';Service='BITS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] ClipSVC (WSAPPX)';Program='C:\Windows\System32\svchost.exe';Service='ClipSVC';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] CompPkgSrv.exe';Program='C:\Windows\System32\CompPkgSrv.exe';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DoSvc';Program='C:\Windows\System32\svchost.exe';Service='DoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DsmSvc';Program='C:\Windows\System32\svchost.exe';Service='DsmSvc';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] IKEEXT';Program='C:\Windows\System32\svchost.exe';Service='IKEEXT';Protocol='UDP';LPort='500';RPort='500';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] InstallService';Program='C:\Windows\System32\svchost.exe';Service='InstallService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] LicenseManager';Program='C:\Windows\System32\svchost.exe';Service='LicenseManager';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] MoUsoCoreWorker';Program='C:\Windows\System32\svchost.exe';Service='MoUsoCoreWorker';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] NetworkService';Program='C:\Windows\System32\svchost.exe';Service='NetworkService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] NlaSvc';Program='C:\Windows\System32\svchost.exe';Service='NlaSvc';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Schedule';Program='C:\Windows\System32\svchost.exe';Service='Schedule';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] ShellHWDetection';Program='C:\Windows\System32\svchost.exe';Service='ShellHWDetection';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] taskhostw.exe';Program='C:\Windows\System32\taskhostw.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] TokenBroker';Program='C:\Windows\System32\svchost.exe';Service='TokenBroker';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UnistackSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UnistackSvcGroup';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UserManager';Program='C:\Windows\System32\svchost.exe';Service='UserManager';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UserProfileService';Program='C:\Windows\System32\svchost.exe';Service='UserProfileService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UsoSvc';Program='C:\Windows\System32\svchost.exe';Service='UsoSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] VaultSvc';Program='C:\Windows\System32\svchost.exe';Service='VaultSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WaaSMedicSvc';Program='C:\Windows\System32\svchost.exe';Service='WaaSMedicSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WinHttpAutoProxySvc';Program='C:\Windows\System32\svchost.exe';Service='WinHttpAutoProxySvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] Winmgmt';Program='C:\Windows\System32\svchost.exe';Service='Winmgmt';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wlidsvc';Program='C:\Windows\System32\svchost.exe';Service='wlidsvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WpnService';Program='C:\Windows\System32\svchost.exe';Service='WpnService';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wuauserv';Program='C:\Windows\System32\svchost.exe';Service='wuauserv';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] AppIdCertStoreCheck.exe';Program='C:\Windows\System32\AppIdCertStoreCheck.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] backgroundTaskHost.exe';Program='C:\Windows\System32\backgroundTaskHost.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] BDESVC';Program='C:\Windows\System32\svchost.exe';Service='BDESVC';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] camsvc';Program='C:\Windows\System32\svchost.exe';Service='camsvc';Protocol='Any';LPort='*';RPort='80';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CompatTelRunner.exe';Program='C:\Windows\System32\CompatTelRunner.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] dasHost.exe (device pairing)';Program='C:\Windows\System32\dashost.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DcomLaunch';Program='C:\Windows\System32\svchost.exe';Service='DcomLaunch';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DevicesFlow (bluetooth)';Program='C:\Windows\System32\svchost.exe';Service='DevicesFlow';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DiagTrack';Program='C:\Windows\System32\svchost.exe';Service='DiagTrack';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Dnscache (mDNS/Local Discovery)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';LPort='*';RPort='5353';RAddr='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Dnscache LocalSubnet (mDNS/Local Discovery)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';LPort='*';RPort='5353';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] EventLog RPC INBOUND';Program='C:\Windows\System32\svchost.exe';Service='EventLog';Protocol='TCP';LPort='135';Action='Block';Profile='Domain,Private';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] explorer.exe';Program='C:\Windows\explorer.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP INBOUND';Program='System';Protocol='2';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP OUTBOUND';Program='System';Protocol='2';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='139';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='445';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='UDP';LPort='137';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanServer INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='UDP';LPort='138';RPort='*';RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanWorkstation';Program='C:\Windows\System32\svchost.exe';Service='LanmanWorkstation';Protocol='TCP';LPort='*';RPort=@('445','443');RAddr='LocalSubnet';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] lsass.exe (for domain environment)';Program='C:\Windows\System32\lsass.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MpCmdRun.exe';Program='C:\Program Files (x86)\Windows Defender\MpCmdRun.exe';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MpCmdRun.exe';Program='C:\Program Files\Windows Defender\MpCmdRun.exe';Protocol='TCP';LPort='*';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] OneSyncSvc';Program='C:\Windows\System32\svchost.exe';Service='OneSyncSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] osprivacy';Program='C:\Windows\System32\svchost.exe';Service='osprivacy';Protocol='Any';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote L2TP UDP INBOUND';Program='System';Protocol='UDP';LPort='1701';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote L2TP UDP OUTBOUND';Program='System';Protocol='UDP';RPort='1701';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote PPTP TCP INBOUND';Program='System';Protocol='TCP';LPort='1723';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote PPTP TCP OUTBOUND';Program='System';Protocol='TCP';RPort='1723';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote protocol 47 GRE INBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote protocol 47 GRE OUTBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='TCP';LPort='3389';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP TCP OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='TCP';RPort='3389';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP UDP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='UDP';LPort='3389';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RPC Dynamic Ports INBOUND';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='49152-65535';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RPC TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Protocol='TCP';LPort='135';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote SMB TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='TCP';LPort='445';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote WinRM TCP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='TCP';LPort='5985-5986';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] RPCSS';Program='C:\Windows\System32\svchost.exe';Service='RPCSS';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SENS';Program='C:\Windows\System32\svchost.exe';Service='SENS';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] spoolsv.exe (printer)';Program='C:\Windows\System32\spoolsv.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TimeBrokerSvc INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TimeBrokerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] UdkSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UdkSvcGroup';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] W32Time';Program='C:\Windows\System32\svchost.exe';Service='W32Time';Protocol='UDP';LPort='*';RPort='123';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WerSvc';Program='C:\Windows\System32\svchost.exe';Service='WerSvc';Protocol='TCP';LPort='*';RPort=@('80','443');Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] wfcUI.exe (allow for updates)';Program='C:\Program Files\Malwarebytes\Windows Firewall Control\wfcUI.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] wininit.exe';Program='C:\Windows\System32\wininit.exe';Protocol='TCP';LPort='*';RPort='*';Action='Block';Profile='Any';Direction='Outbound'}
)
$log = "$([Environment]::GetFolderPath('Desktop'))\FirewallRules.log"
foreach($r in $rules){
    $p = @{
        DisplayName = $r.Name
        Direction   = $r.Direction
        Action      = $r.Action
        Protocol    = $r.Protocol
        Profile     = $r.Profile
        Enabled     = 'True'
        Group       = 'Windows Firewall Control'
    }
    if($r.Program){ $p.Program = $r.Program }
    if($r.Service){ $p.Service = $r.Service }
    if($r.Protocol -in 'TCP','UDP'){
        if($r.LPort -ne '*'){ $p.LocalPort  = $r.LPort }
        if($r.RPort -ne '*'){ $p.RemotePort = $r.RPort }
    }
    if($r.LAddr -and $r.LAddr -ne 'Any'){
        $p.LocalAddress = $r.LAddr -split ','
    }
    if($r.RAddr -and $r.RAddr -ne 'Any'){

        if($r.Url){ "NOTE: $($r.Url)" >> $log }

        $tokens = $r.RAddr -split ','
        $valid  = $tokens | ?{
            $_ -match '^[\d\.\/:A-Fa-f]+$' -or
            $_ -in @('LocalSubnet','Internet','Intranet','DNS','Any','DefaultGateway')
        }
        if($valid.Count){
            $p.RemoteAddress = $valid
        }
        else {
            "SKIP: $($r.Name)" >> $log
            continue
        }
    }
    try {
        $rule = New-NetFirewallRule @p -EA Stop
        if($r.Enabled -eq 'False'){
            Set-NetFirewallRule -Name $rule.Name -Enabled False
        }
        "SUCCESS: $($r.Name)" >> $log
    }
    catch {
        "FAILED: $($r.Name) $($_.Exception.Message)" >> $log
    }
}
$base = "C:\Windows\System32\DriverStore\FileRepository"
$targets = Get-ChildItem $base -Directory -Filter "nv_dispi.inf_amd64_*" -EA 0 |
  ForEach-Object {
    @(
      Join-Path $_.FullName "Display.NvContainer\NVDisplay.Container.exe"
    )
  } | Where-Object {Test-Path $_}
foreach($exe in $targets){
  try{
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING] $([IO.Path]::GetFileName($exe))" `
      -Direction Outbound -Action Block -Program $exe `
      -Protocol TCP -LocalPort Any -RemotePort Any -Profile Any -Enabled True `
      -Group "Windows Firewall Control"
    "SUCCESS: $exe" >> $log
  }catch{
    "FAILED: $exe $($_.Exception.Message)" >> $log
  }
}
$base = "C:\Windows\System32\DriverStore\FileRepository"
$targets = Get-ChildItem $base -Directory -Filter "nv_dispi.inf_amd64_*" -EA 0 |
  ForEach-Object {
    @(
      Join-Path $_.FullName "nvngx_update.exe"
    )
  } | Where-Object {Test-Path $_}
foreach($exe in $targets){
  try{
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING] $([IO.Path]::GetFileName($exe))" `
      -Direction Outbound -Action Block -Program $exe `
      -Protocol TCP -LocalPort Any -RemotePort Any -Profile Any -Enabled True `
      -Group "Windows Firewall Control"
    "SUCCESS: $exe" >> $log
  }catch{
    "FAILED: $exe $($_.Exception.Message)" >> $log
  }
}
```
