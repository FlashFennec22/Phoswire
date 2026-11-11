; Phoswire installer (Inno Setup 6.3+).
;
; Build the binary first, then compile this script:
;   cargo build --release
;   ISCC.exe installer\phoswire.iss
;
; The install folder must stay {autopf}\Phoswire: `phoswire install` registers
; the service at %ProgramFiles%\Phoswire\phoswire.exe.

#define AppName "Phoswire"
#define AppVersion "0.2.0"
#define AppExe "phoswire.exe"

[Setup]
AppId={{6C1B3F0E-52A7-4E0B-9A3D-7F1E2C4D8B90}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
ChangesEnvironment=yes
OutputDir=Output
OutputBaseFilename=phoswire-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName} Firewall
CloseApplications=no

[Tasks]
Name: "learning"; Description: "Start in &learning mode (recommended; otherwise every app is blocked until you whitelist it)"; Check: IsFreshInstall
Name: "path"; Description: "Add Phoswire to the system &PATH so `phoswire` works from any terminal"

[Files]
Source: "..\target\release\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: path; Check: NeedsAddPath(ExpandConstant('{app}'))

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "uninstall"; Flags: runhidden; RunOnceId: "RemovePhoswireService"

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function ConfigFile: String;
begin
  Result := ExpandConstant('{commonappdata}\Phoswire\config.json');
end;

{ A whitelist from an earlier install is kept, and so is its mode. }
function IsFreshInstall: Boolean;
begin
  Result := not FileExists(ConfigFile);
end;

function NeedsAddPath(Dir: String): Boolean;
var
  Paths: String;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Paths) then
    Result := True
  else
    Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

procedure RemovePath(Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  { P is where Dir starts in Paths; remove it and the separator after it. }
  Delete(Paths, P, Length(Dir) + 1);
  { If it was the last entry, drop the separator that preceded it. }
  if (P > Length(Paths)) and (Length(Paths) > 0) and (Paths[Length(Paths)] = ';') then
    Delete(Paths, Length(Paths), 1);
  RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Paths);
end;

{ On an upgrade the running service holds phoswire.exe open; stop it first.
  `phoswire stop` returns once the service has actually stopped. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Exe: String;
  Code: Integer;
begin
  Result := '';
  Exe := ExpandConstant('{app}\{#AppExe}');
  if FileExists(Exe) then
    Exec(Exe, 'stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

{ Registers and starts the service once the files are in place.

  `phoswire install` itself creates the data folder, restricted to SYSTEM and
  Administrators, and writes the initial configuration; setup must not create
  that folder, because one made here would inherit ProgramData's permissions,
  which let any user add files to it.

  The result is checked: a firewall that silently failed to install is worse
  than an installer that says so. }
procedure CurStepChanged(CurStep: TSetupStep);
var
  Params: String;
  Code: Integer;
  Started: Boolean;
begin
  if CurStep <> ssPostInstall then
    exit;
  Params := 'install';
  if WizardIsTaskSelected('learning') then
    Params := Params + ' --learning';
  WizardForm.StatusLabel.Caption := 'Registering and starting the Phoswire service...';
  Started := Exec(ExpandConstant('{app}\{#AppExe}'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code);
  if (not Started) or (Code <> 0) then
    SuppressibleMsgBox(
      'The Phoswire service could not be installed or started, so this computer is NOT being filtered.' + #13#10#13#10 +
      'Open an elevated terminal and run "phoswire install" to see the reason.',
      mbCriticalError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemovePath(ExpandConstant('{app}'));
end;
