; Phoswire installer (Inno Setup 6.3+).
;
; Build the binary first, then compile this script:
;   cargo build --release
;   ISCC.exe installer\phoswire.iss
;
; The install folder must stay {autopf}\Phoswire: `phoswire install` registers
; the service at %ProgramFiles%\Phoswire\phoswire.exe.

#define AppName "Phoswire"
#define AppVersion "0.1.0"
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

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "install"; StatusMsg: "Registering and starting the Phoswire service..."; Flags: runhidden; BeforeInstall: WriteInitialConfig

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

{ Runs just before the service is registered and started. }
procedure WriteInitialConfig;
begin
  if WizardIsTaskSelected('learning') and IsFreshInstall then
  begin
    ForceDirectories(ExtractFileDir(ConfigFile));
    SaveStringToFile(ConfigFile, '{"mode":"learning","rules":[]}', False);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemovePath(ExpandConstant('{app}'));
end;
