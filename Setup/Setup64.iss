[Setup]
;-- Main Setup Information
 AppName                         = IP Traffic Spy
 AppVerName                      = IP Traffic Spy 1.0.0.8
 AppCopyright                    = Copyright © 1995-2017 NetworkDLS.
 DefaultDirName                  = {pf}\NetworkDLS\IP Traffic Spy
 DefaultGroupName                = NetworkDLS\IP Traffic Spy
 UninstallDisplayIcon            = {app}\Resources\IP Traffic Spy.ico
 WizardImageFile                 = ..\..\@Resources\Setup\LgSetup.bmp
 WizardSmallImageFile            = ..\..\@Resources\Setup\SmSetup.bmp
 PrivilegesRequired              = Admin
 Uninstallable                   = Yes
 AppMutex                        = IP Traffic Spy
 LicenseFile                     = ..\..\@Resources\Setup\License\EULA.txt
 Compression                     = ZIP/9
 OutputBaseFilename              = IPSpy64
 MinVersion                      = 0.0,5.0
 ArchitecturesInstallIn64BitMode = x64
 ArchitecturesAllowed            = x64

;-- Windows 2000 & XP (Support Dialog)
 AppPublisher    = NetworkDLS
 AppPublisherURL = http://www.NetworkDLS.com/
 AppUpdatesURL   = http://www.NetworkDLS.com/
 AppVersion      = 1.0.0.8

[Files]
 Source: "..\..\@AutoUpdate\x64\Release\AutoUpdate.Exe";      DestDir: "{app}\Bin"; Flags: RestartReplace;
 Source: "AutoUpdate.xml";                       DestDir: "{app}"; Flags: IgnoreVersion;
 Source: "..\Release\x64\ISpy.Exe";              DestDir: "{app}"; Flags: IgnoreVersion;
 Source: "Help File\Help.Chm";                   DestDir: "{app}";
 Source: "Resources\*.*";                        DestDir: "{app}\Resources";

[Icons]
 Name: "{group}\IP Traffic Spy";  Filename: "{app}\ISpy.Exe";
 Name: "{group}\Help";            Filename: "{app}\Help.Chm";
 Name: "{group}\Uninstall";       Filename: "{uninstallexe}";
 Name: "{group}\AutoUpdate";      Filename: "{app}\AutoUpdate.Exe";

[Registry]
 Root: HKLM; Subkey: "Software\NetworkDLS\IP Traffic Spy"; Flags: uninsdeletekey noerror;
 Root: HKLM; Subkey: "Software\NetworkDLS\IP Traffic Spy"; ValueName: "Path"; ValueType: String;  ValueData: "{app}"

[Run]
 Filename: "{app}\ISpy.Exe"; Description: "Launch application"; Flags: postinstall nowait skipifsilent shellexec;

