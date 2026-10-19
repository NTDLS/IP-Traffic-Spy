[Setup]
;-- Main Setup Information
 AppName                         = IP Traffic Spy
 AppVerName                      = IP Traffic Spy 1.0.1.0
 AppCopyright                    = Copyright © 1995-2026 NetworkDLS.
 DefaultDirName                  = {commonpf}\NetworkDLS\IP Traffic Spy
 DefaultGroupName                = NetworkDLS\IP Traffic Spy
 UninstallDisplayIcon            = {app}\Resources\IP Traffic Spy.ico
 PrivilegesRequired              = Admin
 Uninstallable                   = Yes
 AppMutex                        = IP Traffic Spy
 Compression                     = bZIP/9
 OutputBaseFilename              = IPSpy64
 ArchitecturesInstallIn64BitMode = x64os
 ArchitecturesAllowed            = x64Compatible
 SetupIconFile                   = ..\Resources\MainIcon.ico
  
;-- Windows 2000 & XP (Support Dialog)
 AppPublisher    = NetworkDLS
 AppPublisherURL = http://www.NetworkDLS.com/
 AppUpdatesURL   = http://www.NetworkDLS.com/
 AppVersion      = 1.0.1.0

[Files]
 Source: "..\Release\x64\ISpy.Exe";              DestDir: "{app}"; Flags: IgnoreVersion;
 Source: "Help File\Help.Chm";                   DestDir: "{app}";
 Source: "Resources\*.*";                        DestDir: "{app}\Resources";

[Icons]
 Name: "{group}\IP Traffic Spy";  Filename: "{app}\ISpy.Exe";
 Name: "{group}\Help";            Filename: "{app}\Help.Chm";
 Name: "{group}\Uninstall";       Filename: "{uninstallexe}";

[Registry]
 Root: HKLM; Subkey: "Software\NetworkDLS\IP Traffic Spy"; Flags: uninsdeletekey noerror;
 Root: HKLM; Subkey: "Software\NetworkDLS\IP Traffic Spy"; ValueName: "Path"; ValueType: String;  ValueData: "{app}"

[Run]
 Filename: "{app}\ISpy.Exe"; Description: "Launch application"; Flags: postinstall nowait skipifsilent shellexec;

