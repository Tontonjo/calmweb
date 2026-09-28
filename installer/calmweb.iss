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
Source: "scheduled_task.xml"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: PatchScheduledTaskXml

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{app}\Uninstall\unins000.exe"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
; Add firewall rule
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=CalmWeb dir=in action=allow program=""{app}\{#MyAppExeName}"" profile=any"; Flags: runhidden
; Create scheduled task
Filename: "schtasks"; Parameters: "/Create /tn CalmWeb /XML ""{app}\scheduled_task.xml"" /F"; Flags: runhidden
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
; Delete scheduled task
Filename: "schtasks"; Parameters: "/Delete /tn CalmWeb /F"; Flags: runhidden; RunOnceId: "DeleteScheduledTask"
; Reset system proxy
Filename: "netsh"; Parameters: "winhttp reset proxy"; Flags: runhidden; RunOnceId: "ResetWinHttpProxy"

[UninstallDelete]
Type: files; Name: "{userappdata}\CalmWeb\calmweb.lock"

[Code]
procedure PatchScheduledTaskXml();
var
  FilePath: String;
  FileContent: AnsiString;
  NewContent: String;
begin
  FilePath := ExpandConstant('{app}\scheduled_task.xml');
  if LoadStringFromFile(FilePath, FileContent) then
  begin
    NewContent := String(FileContent);
    StringChangeEx(NewContent, '__INSTALL_DIR__', ExpandConstant('{app}'), True);
    SaveStringToFile(FilePath, AnsiString(NewContent), False);
  end;
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
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Reset proxy registry settings }
    RegWriteDWordValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', 0);
    RegWriteStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer', '');
  end;
end;
