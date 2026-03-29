# LDFRS (PowerShell script) v0.4.9
##### this is for Malwarebytes Windows Firewall Control
##### you can make this for any firewall though
## what to do:
##### use [Registry-Tweaks-Refresh](https://github.com/smo0ths/Registry-Tweaks-Refresh.bat) and [My-Network-Adaptor-Settings](https://github.com/smo0ths/My-Network-Adaptor-Settings) with this
#
#### Malwarebytes Windows Firewall Control settings (from main panel):
* ##### Profiles: *medium*
* ##### Notifications: *check display, set close notification to 999, default advanced notifications settings is fine
* ##### Options: *check shell/start*
* ##### Rules: *check outbound/domain/private/public*
* ##### Security: *check secure profile and delete unauthorized groups though (press - on all other authorized groups keep WFC and temp rules)*
* ##### Rules Panel: *open delete/block rules you don't want*
#
* ##### *if check secure rules(w/ disable unauthorized rules) change disabled rules group name Windows Firewall Control and enable if you want to keep rule*
* ##### *set ALLOW to the [UPDATES/CERTS/IDENTITY/LICENSING] and/or [BLOCK IF NOT USING] if needed*
* ##### *right click block .exe's before opening them*
* ##### *just click allow/block button unless blocking single port (click customize this rule before creating it > uncheck local ports/remote IP)
#
## copy/paste in PowerShell:
#
```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*';
Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ [UPDATES] DoSvc';Program='C:\Windows\System32\svchost.exe';Service='DoSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES] InstallService';Program='C:\Windows\System32\svchost.exe';Service='InstallService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES] UsoSvc';Program='C:\Windows\System32\svchost.exe';Service='UsoSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES/CERTS] BITS';Program='C:\Windows\System32\svchost.exe';Service='BITS';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES/CERTS] CryptSvc';Program='C:\Windows\System32\svchost.exe';Service='CryptSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES/CERTS] sppsvc';Program='C:\Windows\System32\svchost.exe';Service='sppsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [UPDATES/CERTS] wuauserv';Program='C:\Windows\System32\svchost.exe';Service='wuauserv';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [IDENTITY/LICENSING] ClipSVC';Program='C:\Windows\System32\svchost.exe';Service='ClipSVC';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [IDENTITY/LICENSING] LicenseManager';Program='C:\Windows\System32\svchost.exe';Service='LicenseManager';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [IDENTITY/LICENSING] OneSyncSvc';Program='C:\Windows\System32\svchost.exe';Service='OneSyncSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [IDENTITY/LICENSING] TokenBroker';Program='C:\Windows\System32\svchost.exe';Service='TokenBroker';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ [IDENTITY/LICENSING] wlidsvc';Program='C:\Windows\System32\svchost.exe';Service='wlidsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DHCP Client';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='67';RPort='68';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv4 INBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv4 OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='68';RPort='67';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DHCPv6 INBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv6 OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='UDP';LPort='546';RPort='547';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 INBOUND';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 OUTBOUND';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow ICMPv6 INBOUND';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='129'},
@{Name='✔️ Allow ICMPv6 OUTBOUND';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='128'},
@{Name='✔️ Allow Dnscache OUTBOUND TCP/53 (HTTP)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';RPort='53';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Dnscache OUTBOUND UDP/53 (HTTP)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';RPort='53';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Dnscache OUTBOUND TCP/443 (HTTPS)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow Dnscache OUTBOUND UDP/443 (HTTPS)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';RPort='443';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow/Block Dnscache INBOUND UDP/5353 (mDNS)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';RPort='5353';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow/Block Dnscache OUTBOUND UDP/5353 (mDNS)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';RPort='5353';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow/Block Everything OUTBOUND TCP/443 (HTTPS)';Program='Any';Service='Any';Protocol='TCP';RPort='443';Action='Block';Profile='Any';Direction='Outbound';Enabled='False'},
@{Name='✔️ Allow/Block Everything OUTBOUND TCP/80 (HTTP)';Program='Any';Service='Any';Protocol='TCP';RPort='80';Action='Block';Profile='Any';Direction='Outbound';Enabled='False'},
@{Name='✔️ Allow/Block Everything OUTBOUND UDP/443 (HTTPS)';Program='Any';Service='Any';Protocol='UDP';RPort='443';Action='Block';Profile='Any';Direction='Outbound';Enabled='False'},
@{Name='✔️ Allow/Block netprofm';Program='C:\Windows\System32\svchost.exe';Service='netprofm';Protocol='Any';Action='Allow';Profile='Any';Direction='Outbound';Enabled='True'},
@{Name='✖ [BLOCK IF NOT USING EXE] explorer.exe';Program='C:\Windows\explorer.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING EXE] lsass.exe';Program='C:\Windows\System32\lsass.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING EXE] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING EXE] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING EXE] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING EXE] taskhostw.exe';Program='C:\Windows\System32\taskhostw.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] appmodel';Program='C:\Windows\System32\svchost.exe';Service='appmodel';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] AppReadiness';Program='C:\Windows\System32\svchost.exe';Service='AppReadiness';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] AppXSvc';Program='C:\Windows\System32\svchost.exe';Service='AppXSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] BDESVC';Program='C:\Windows\System32\svchost.exe';Service='BDESVC';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] camsvc';Program='C:\Windows\System32\svchost.exe';Service='camsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] dcsvc';Program='C:\Windows\System32\svchost.exe';Service='dcsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] DevicesFlow';Program='C:\Windows\System32\svchost.exe';Service='DevicesFlow';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] DiagTrack';Program='C:\Windows\System32\svchost.exe';Service='DiagTrack';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] DsmSvc';Program='C:\Windows\System32\svchost.exe';Service='DsmSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] gpsvc';Program='C:\Windows\System32\svchost.exe';Service='gpsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] IKEEXT';Program='C:\Windows\System32\svchost.exe';Service='IKEEXT';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] iphlpsvc';Program='C:\Windows\System32\svchost.exe';Service='iphlpsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] LanmanWorkstation';Program='C:\Windows\System32\svchost.exe';Service='LanmanWorkstation';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] LxpSvc';Program='C:\Windows\System32\svchost.exe';Service='LxpSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] MapsBroker';Program='C:\Windows\System32\svchost.exe';Service='MapsBroker';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] NlaSvc';Program='C:\Windows\System32\svchost.exe';Service='NlaSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] osprivacy';Program='C:\Windows\System32\svchost.exe';Service='osprivacy';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] SENS';Program='C:\Windows\System32\svchost.exe';Service='SENS';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] ShellHWDetection';Program='C:\Windows\System32\svchost.exe';Service='ShellHWDetection';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] swprv';Program='C:\Windows\System32\svchost.exe';Service='swprv';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] TimeBrokerSvc';Program='C:\Windows\System32\svchost.exe';Service='TimeBrokerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] UdkSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UdkSvcGroup';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] UnistackSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UnistackSvcGroup';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] W32Time';Program='C:\Windows\System32\svchost.exe';Service='W32Time';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WaaSMedicSvc';Program='C:\Windows\System32\svchost.exe';Service='WaaSMedicSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WdiSystemHost';Program='C:\Windows\System32\svchost.exe';Service='WdiSystemHost';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WerSvc';Program='C:\Windows\System32\svchost.exe';Service='WerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WFDSConMgrSvc';Program='C:\Windows\System32\svchost.exe';Service='WFDSConMgrSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WinHttpAutoProxySvc';Program='C:\Windows\System32\svchost.exe';Service='WinHttpAutoProxySvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] Winmgmt';Program='C:\Windows\System32\svchost.exe';Service='Winmgmt';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] wisvc';Program='C:\Windows\System32\svchost.exe';Service='wisvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] wmiApSrv';Program='C:\Windows\System32\svchost.exe';Service='wmiApSrv';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SERVICE] WpnService';Program='C:\Windows\System32\svchost.exe';Service='WpnService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING STUFF] LanmanServer SMB INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING STUFF] TermService RDP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING STUFF] TermService RDP OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING STUFF] WinRM INBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING STUFF] WinRM OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SYSTEM] IGMP INBOUND';Program='System';Protocol='2';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING SYSTEM] IGMP OUTBOUND';Program='System';Protocol='2';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING SYSTEM] Remote GRE INBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING SYSTEM] Remote GRE OUTBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Outbound'}
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
$targets = Get-ChildItem $base -Directory -Filter "nv_disp*" -EA 0 |
  ForEach-Object {
    @(
      Join-Path $_.FullName "Display.NvContainer\NVDisplay.Container.exe"
    )
  } | Where-Object {Test-Path $_}
foreach($exe in $targets){
  try{
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING NVIDIA] $([IO.Path]::GetFileName($exe))" `
      -Direction Outbound -Action Block -Program $exe `
      -Protocol Any -LocalPort Any -RemotePort Any -Profile Any -Enabled True `
      -Group "Windows Firewall Control"
    "SUCCESS: $exe" >> $log
  }catch{
    "FAILED: $exe $($_.Exception.Message)" >> $log
  }
}
$base = "C:\Windows\System32\DriverStore\FileRepository"
$targets = Get-ChildItem $base -Directory -Filter "nv_disp*" -EA 0 |
  ForEach-Object {
    @(
      Join-Path $_.FullName "nvngx_update.exe"
    )
  } | Where-Object {Test-Path $_}
foreach($exe in $targets){
  try{
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING NVIDIA] $([IO.Path]::GetFileName($exe))" `
      -Direction Outbound -Action Block -Program $exe `
      -Protocol Any -LocalPort Any -RemotePort Any -Profile Any -Enabled True `
      -Group "Windows Firewall Control"
    "SUCCESS: $exe" >> $log
  }catch{
    "FAILED: $exe $($_.Exception.Message)" >> $log
  }
}
```
