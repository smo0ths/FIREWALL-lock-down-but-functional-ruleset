# LDFRS (PowerShell script) v0.4.3
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
* ##### *set ALLOW to the [BLOCK IF UPDATES DISABLED] and [BLOCK IF NOT USING] if needed*
* ##### *right click block apps before opening them*
* ##### *just click allow/block button unless blocking single port (click customize this rule before creating it > uncheck local ports/remote IP)
#
## copy/paste in PowerShell:
#
```python
# lock‑down but functional ruleset LDFRS (PowerShell script)
$patterns='*✔️*','*✖*';
Get-NetFirewallRule -DisplayName $patterns -EA 0 | ? Group -eq 'Windows Firewall Control' | Remove-NetFirewallRule
$rules = @(
@{Name='✔️ Allow DHCPv4/v6 INBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='Any';Action='Allow';Profile='Any';Direction='Inbound'},
@{Name='✔️ Allow DHCPv4/v6 OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='Dhcp';Protocol='Any';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow DNS OUTBOUND TCP (DoH)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';RPort='443';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✖ Block DNS OUTBOUND TCP (plaintext)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='TCP';RPort='53';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ Block DNS OUTBOUND UDP (plaintext)';Program='C:\Windows\System32\svchost.exe';Service='Dnscache';Protocol='UDP';RPort='53';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✔️ Allow ICMPv4 INBOUND';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='0'},
@{Name='✔️ Allow ICMPv4 OUTBOUND';Program='System';Protocol='1';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='8'},
@{Name='✔️ Allow ICMPv6 INBOUND';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Inbound';IcmpType='129'},
@{Name='✔️ Allow ICMPv6 OUTBOUND';Program='System';Protocol='58';Action='Allow';Profile='Any';Direction='Outbound';IcmpType='128'},
@{Name='✔️ Allow netprofm';Program='C:\Windows\System32\svchost.exe';Service='netprofm';Protocol='Any';Action='Allow';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] BITS';Program='C:\Windows\System32\svchost.exe';Service='BITS';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] DoSvc';Program='C:\Windows\System32\svchost.exe';Service='DoSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] InstallService';Program='C:\Windows\System32\svchost.exe';Service='InstallService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] MoUsoCoreWorker.exe';Program='C:\Windows\UUS\amd64\MoUsoCoreWorker.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] SIHClient.exe';Program='C:\Windows\System32\SIHClient.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] UsoSvc';Program='C:\Windows\System32\svchost.exe';Service='UsoSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WaaSMedicAgent.exe';Program='C:\Windows\UUS\amd64\WaaSMedicAgent.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WaaSMedicSvc';Program='C:\Windows\System32\svchost.exe';Service='WaaSMedicSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] WinHttpAutoProxySvc';Program='C:\Windows\System32\svchost.exe';Service='WinHttpAutoProxySvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF UPDATES DISABLED] wuauserv';Program='C:\Windows\System32\svchost.exe';Service='wuauserv';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] AppIdCertStoreCheck.exe';Program='C:\Windows\System32\AppIdCertStoreCheck.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] appmodel';Program='C:\Windows\System32\svchost.exe';Service='appmodel';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] AppXSvc';Program='C:\Windows\System32\svchost.exe';Service='AppXSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] backgroundTaskHost.exe';Program='C:\Windows\System32\backgroundTaskHost.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] BDESVC';Program='C:\Windows\System32\svchost.exe';Service='BDESVC';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] camsvc';Program='C:\Windows\System32\svchost.exe';Service='camsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] ClipSVC';Program='C:\Windows\System32\svchost.exe';Service='ClipSVC';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CompatTelRunner.exe';Program='C:\Windows\System32\CompatTelRunner.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CompPkgSrv.exe';Program='C:\Windows\System32\CompPkgSrv.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] CryptSvc';Program='C:\Windows\System32\svchost.exe';Service='CryptSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] dcsvc';Program='C:\Windows\System32\svchost.exe';Service='dcsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DevicesFlow';Program='C:\Windows\System32\svchost.exe';Service='DevicesFlow';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DiagTrack';Program='C:\Windows\System32\svchost.exe';Service='DiagTrack';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] DsmSvc';Program='C:\Windows\System32\svchost.exe';Service='DsmSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] EventLog RPC INBOUND';Program='C:\Windows\System32\svchost.exe';Service='EventLog';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] explorer.exe';Program='C:\Windows\explorer.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] gpsvc';Program='C:\Windows\System32\svchost.exe';Service='gpsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP INBOUND';Program='System';Protocol='2';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] IGMP OUTBOUND';Program='System';Protocol='2';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] IKEEXT';Program='C:\Windows\System32\svchost.exe';Service='IKEEXT';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] iphlpsvc';Program='C:\Windows\System32\svchost.exe';Service='iphlpsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LanmanWorkstation';Program='C:\Windows\System32\svchost.exe';Service='LanmanWorkstation';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LicenseManager';Program='C:\Windows\System32\svchost.exe';Service='LicenseManager';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] lsass.exe';Program='C:\Windows\System32\lsass.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] LxpSvc';Program='C:\Windows\System32\svchost.exe';Service='LxpSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MapsBroker';Program='C:\Windows\System32\svchost.exe';Service='MapsBroker';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MpCmdRun.exe';Program='C:\Program Files (x86)\Windows Defender\MpCmdRun.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] MpCmdRun.exe';Program='C:\Program Files\Windows Defender\MpCmdRun.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] NlaSvc';Program='C:\Windows\System32\svchost.exe';Service='NlaSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] OneSyncSvc';Program='C:\Windows\System32\svchost.exe';Service='OneSyncSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] osprivacy';Program='C:\Windows\System32\svchost.exe';Service='osprivacy';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote GRE INBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote GRE OUTBOUND';Program='System';Protocol='47';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP INBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote RDP OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='TermService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote WinRM INBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] Remote WinRM OUTBOUND';Program='C:\Windows\System32\svchost.exe';Service='WinRM';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] rundll32.exe';Program='C:\Windows\System32\rundll32.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SENS';Program='C:\Windows\System32\svchost.exe';Service='SENS';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] ShellHWDetection';Program='C:\Windows\System32\svchost.exe';Service='ShellHWDetection';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SMB INBOUND';Program='C:\Windows\System32\svchost.exe';Service='LanmanServer';Protocol='Any';Action='Block';Profile='Any';Direction='Inbound'},
@{Name='✖ [BLOCK IF NOT USING] spoolsv.exe';Program='C:\Windows\System32\spoolsv.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] SystemSettings.exe';Program='C:\Windows\ImmersiveControlPanel\SystemSettings.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] taskhostw.exe';Program='C:\Windows\System32\taskhostw.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TimeBrokerSvc';Program='C:\Windows\System32\svchost.exe';Service='TimeBrokerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] TokenBroker';Program='C:\Windows\System32\svchost.exe';Service='TokenBroker';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UdkSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UdkSvcGroup';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] UnistackSvcGroup';Program='C:\Windows\System32\svchost.exe';Service='UnistackSvcGroup';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] W32Time';Program='C:\Windows\System32\svchost.exe';Service='W32Time';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WerSvc';Program='C:\Windows\System32\svchost.exe';Service='WerSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] wfcUI.exe';Program='C:\Program Files\Malwarebytes\Windows Firewall Control\wfcUI.exe';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WFDSConMgrSvc';Program='C:\Windows\System32\svchost.exe';Service='WFDSConMgrSvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] wlidsvc';Program='C:\Windows\System32\svchost.exe';Service='wlidsvc';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'},
@{Name='✖ [BLOCK IF NOT USING] WpnService';Program='C:\Windows\System32\svchost.exe';Service='WpnService';Protocol='Any';Action='Block';Profile='Any';Direction='Outbound'}
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
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING] $([IO.Path]::GetFileName($exe))" `
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
    $rule = New-NetFirewallRule -DisplayName "✖ [BLOCK IF NOT USING] $([IO.Path]::GetFileName($exe))" `
      -Direction Outbound -Action Block -Program $exe `
      -Protocol Any -LocalPort Any -RemotePort Any -Profile Any -Enabled True `
      -Group "Windows Firewall Control"
    "SUCCESS: $exe" >> $log
  }catch{
    "FAILED: $exe $($_.Exception.Message)" >> $log
  }
}
```
