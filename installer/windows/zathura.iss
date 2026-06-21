; ZathuraDbg — Windows installer (Inno Setup 6).
;
; Modern, repo-checked-in replacement for the old hand-built script. It is fully
; parameterized — NO machine-specific paths — so it builds identically in CI
; (.github/workflows/windows.yml) and on a developer box.
;
; Build it:
;   ISCC.exe /DMyAppVersion=1.1 /DStagingDir=installer\windows\staging installer\windows\zathura.iss
;
;   * MyAppVersion      display version (CI passes the git tag / VERSION file)
;   * MyAppVersionInfo  optional numeric x.y.z.w for the EXE VersionInfo
;   * StagingDir        a pre-assembled tree (bin\ + assets\) produced by
;                       installer/windows/stage.sh — that script owns the file
;                       list, so this .iss never enumerates DLLs by hand again.
;
; LICENSE / icon paths are RELATIVE to this file (repo-rooted), so a fresh
; checkout just works.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#ifndef StagingDir
  #define StagingDir "staging"
#endif

#define MyAppName "ZathuraDbg"
#define MyAppPublisher "ZathuraDbg"
#define MyAppURL "https://zathura.dev"
#define MyAppExeName "Zathura.exe"
#define RepoRoot "..\.."

[Setup]
; Keep the original AppId so existing installs upgrade in place (do NOT change).
AppId={{1CC103FD-656A-44D9-A383-D0DCBBA448E8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
#ifdef MyAppVersionInfo
VersionInfoVersion={#MyAppVersionInfo}
#endif
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
LicenseFile={#RepoRoot}\LICENSE
; Per-user install by default (no admin prompt); allow /ALLUSERS on the cmdline.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
; x64 only (matches the MinGW64 build); also runs in 64-bit mode on Win11 on Arm.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#RepoRoot}\dist
OutputBaseFilename=ZathuraDbg-{#MyAppVersion}-windows-x64-setup
SetupIconFile={#RepoRoot}\assets\ZathuraIcon.ico
UninstallDisplayIcon={app}\bin\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

; ── Code signing (currently unsigned) ───────────────────────────────────────
; When a cert is available, register a "signtool" named tool in ISCC (or pass
; /Ssigntool=... on the command line) and uncomment these. CI then signs both
; the EXE payload and the installer.
; SignTool=signtool $f
; SignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "armenian"; MessagesFile: "compiler:Languages\Armenian.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "bulgarian"; MessagesFile: "compiler:Languages\Bulgarian.isl"
Name: "catalan"; MessagesFile: "compiler:Languages\Catalan.isl"
Name: "corsican"; MessagesFile: "compiler:Languages\Corsican.isl"
Name: "czech"; MessagesFile: "compiler:Languages\Czech.isl"
Name: "danish"; MessagesFile: "compiler:Languages\Danish.isl"
Name: "dutch"; MessagesFile: "compiler:Languages\Dutch.isl"
Name: "finnish"; MessagesFile: "compiler:Languages\Finnish.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "hebrew"; MessagesFile: "compiler:Languages\Hebrew.isl"
Name: "hungarian"; MessagesFile: "compiler:Languages\Hungarian.isl"
Name: "icelandic"; MessagesFile: "compiler:Languages\Icelandic.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "norwegian"; MessagesFile: "compiler:Languages\Norwegian.isl"
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "slovak"; MessagesFile: "compiler:Languages\Slovak.isl"
Name: "slovenian"; MessagesFile: "compiler:Languages\Slovenian.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "ukrainian"; MessagesFile: "compiler:Languages\Ukrainian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The whole staged tree assembled by installer/windows/stage.sh:
;   {#StagingDir}\bin\Zathura.exe + every DLL it links
;   {#StagingDir}\assets\<fonts, png, ZathuraIcon.ico>
; The app loads ..\assets relative to the EXE (src/utils/fonts.cpp,
; src/main.cpp), so this bin\ + assets\ split is load-bearing — keep it.
Source: "{#StagingDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\bin\{#MyAppExeName}"; WorkingDir: "{app}\bin"; IconFilename: "{app}\assets\ZathuraIcon.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\bin\{#MyAppExeName}"; WorkingDir: "{app}\bin"; IconFilename: "{app}\assets\ZathuraIcon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\bin\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
