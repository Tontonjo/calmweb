; Script revision: 1.8.4
#define MyAppName "CalmWeb"
; Version is injected by build.cmd via /DMyAppVersion=X.Y.Z
; Fallback for manual compilation:
#ifndef MyAppVersion
#define MyAppVersion "0.0.0"
#endif
#define MyAppPublisher "Tonton Jo"
#define MyAppURL "https://github.com/Tontonjo/calmweb"
#define MyAppExeName "calmweb.exe"

[Setup]
AppId={{972FD214-5A8A-4D95-9867-73ACAE1FFA63}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoTextVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppName} Setup
VersionInfoCopyright={#MyAppPublisher}
AppPublisher={#MyAppPublisher}
AppCopyright={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
LicenseFile=..\LICENSE
InfoBeforeFile=info_before_install.txt
InfoAfterFile=info_after_install.txt
OutputDir=..\dist
OutputBaseFilename=CalmWeb_Setup
Compression=lzma2/ultra64
LZMANumBlockThreads=4
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
WizardImageFile=wizard.bmp
WizardSmallImageFile=wizard_small.bmp
SetupIconFile=..\resources\calmweb.ico
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName},0
UninstallFilesDir={app}\Uninstall
CloseApplications=force
CloseApplicationsFilter=calmweb.exe

[Languages]
Name: "french";  MessagesFile: "compiler:Languages\French.isl"

[Files]
Source: "..\dist\calmweb_installer.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "..\resources\calmweb.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\resources\calmweb_active.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\resources\calmweb_icon.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\resources\calmweb_active.png"; DestDir: "{app}"; DestName: "calmweb_active.png"; Flags: ignoreversion

[InstallDelete]
; Left behind by 1.7.x, which started CalmWeb from a scheduled task
Type: files; Name: "{app}\scheduled_task.xml"

[Registry]
; Start CalmWeb at logon for every user (replaces the 1.7.x scheduled task).
; HKLM64 so the value lands in the 64-bit view, which Windows reads first.
Root: HKLM64; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CalmWeb"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Check: IsWin64
Root: HKLM32; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CalmWeb"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Check: not IsWin64

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{app}\Uninstall\unins000.exe"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
; Add firewall rule
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=CalmWeb dir=in action=allow program=""{app}\{#MyAppExeName}"" profile=any"; Flags: runhidden
; Remove the 1.7.x logon scheduled task (no-op when absent)
Filename: "schtasks"; Parameters: "/Delete /tn CalmWeb /F"; Flags: runhidden
; Remove the legacy QUIC firewall rule of older versions (no-op when absent),
; so the application never has to elevate to do it
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""CalmWeb - Force HTTP3 fallback"""; Flags: runhidden
; Launch after install (optional)
; Started through cmd so the PyInstaller bootloader variables are cleared
; first. During an in-app update, Setup inherits _PYI_* from the running copy
; that launched it and would hand them to the copy started here; because the
; installer overwrites calmweb.exe in place, _PYI_ARCHIVE_FILE still names the
; right path, so the bootloader believes a onefile parent spawned it, checks
; that parent, finds CalmWeb_Setup.exe and aborts with
;   Security validation failure: parent process has different executable!
; calmweb.updater clears them on its side too, but only a version that already
; carries that fix can; this covers the update coming *from* an older one.
; `start ""` also detaches the app so it does not die with the shell.
Filename: "{cmd}"; Parameters: "/C set ""_PYI_ARCHIVE_FILE="" & set ""_PYI_APPLICATION_HOME_DIR="" & set ""_PYI_PARENT_PROCESS_LEVEL="" & set ""_PYI_SPLASH_IPC="" & start """" ""{app}\{#MyAppExeName}"""; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent runhidden

[UninstallRun]
; Kill running instances
Filename: "taskkill"; Parameters: "/IM calmweb.exe /F"; Flags: runhidden; RunOnceId: "KillCalmWeb"
; Remove firewall rule
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=CalmWeb"; Flags: runhidden; RunOnceId: "RemoveFirewallRule"
; Delete the legacy scheduled task, in case a 1.7.x install was never upgraded cleanly
Filename: "schtasks"; Parameters: "/Delete /tn CalmWeb /F"; Flags: runhidden; RunOnceId: "DeleteScheduledTask"
; Reset system proxy
Filename: "netsh"; Parameters: "winhttp reset proxy"; Flags: runhidden; RunOnceId: "ResetWinHttpProxy"

[UninstallDelete]
Type: files; Name: "{userappdata}\CalmWeb\calmweb.lock"

[Code]
{ AppContainer loopback exemptions.
  Packaged applications (new Outlook, new Teams) and the Windows sign-in
  broker are forbidden from reaching 127.0.0.1 unless exempted, so they lose
  the network while the proxy is on. Setting the exemption needs
  administrator rights: Setup already has them, so it is done here once and
  the application never has to show a UAC prompt.
  Keep this list in sync with LOOPBACK_EXEMPT_PACKAGES in
  src/calmweb/platform/windows.py. }
procedure LoopbackExempt(const Action, PackageName: String);
var
  ResultCode: Integer;
  OldRedirection: Boolean;
begin
  OldRedirection := True;
  { CheckNetIsolation lives in the 64-bit System32 on 64-bit Windows. }
  if IsWin64 then
    OldRedirection := EnableFsRedirection(False);
  try
    Exec(ExpandConstant('{sys}\CheckNetIsolation.exe'),
         'LoopbackExempt ' + Action + ' -n=' + PackageName,
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  finally
    if IsWin64 then
      EnableFsRedirection(OldRedirection);
  end;
end;

procedure ApplyLoopbackExemptions(const Action: String);
begin
  LoopbackExempt(Action, 'Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy');
  LoopbackExempt(Action, 'Microsoft.AccountsControl_cw5n1h2txyewy');
  LoopbackExempt(Action, 'Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy');
  LoopbackExempt(Action, 'windows_ie_ac_001');
  LoopbackExempt(Action, 'Microsoft.OutlookForWindows_8wekyb3d8bbwe');
  LoopbackExempt(Action, 'MSTeams_8wekyb3d8bbwe');
end;

procedure InitializeWizard();
begin
  WizardForm.BringToFront;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    { Safety net. CloseApplications=force terminates a running CalmWeb
      outright, and a terminated process cannot undo its own system proxy:
      the machine would be left pointing at 127.0.0.1:8080 with nothing
      listening there. The updater now stops the proxy before starting Setup,
      but a plain reinstall over a running copy has no such handover, so the
      settings are cleared here too. The newly installed copy sets them again
      when it starts.
      Caveat: this writes the hive of whoever answered the UAC prompt, which
      is the same user in the usual admin-approval case only. }
    RegWriteDWordValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', 0);
    RegWriteStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer', '');
    { A force-killed instance leaves its lock file behind, naming a PID that
      Windows may since have handed to another process. }
    DeleteFile(ExpandConstant('{userappdata}\CalmWeb\calmweb.lock'));
  end
  else if CurStep = ssPostInstall then
  begin
    ApplyLoopbackExemptions('-a');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    { Undo the exemptions Setup added. }
    ApplyLoopbackExemptions('-d');
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    { Reset proxy registry settings }
    RegWriteDWordValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', 0);
    RegWriteStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer', '');
  end;
end;
