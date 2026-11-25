; ByteBroom's installer hooks (phase 6, security review M1), included by Tauri's NSIS template
; through bundle.windows.nsis.installerHooks in tauri.installer.json.
;
; ByteBroom installs only into $PROGRAMFILES64\ByteBroom, a folder only administrators can change.
; Anywhere else (C:\Tools, D:\...) ordinary programs could swap ByteBroom, or the uninstaller that
; every update and uninstall runs as administrator. src-tauri/tests/installer.rs pins this file.

; The folder page: "Next" stays greyed out for any other folder.
Function .onVerifyInstDir
  ${If} $INSTDIR != "$PROGRAMFILES64\${PRODUCTNAME}"
    Abort
  ${EndIf}
FunctionEnd

; Silent, passive (updates) and command-line installs skip the folder page, so check again before
; a single file is copied.
!macro NSIS_HOOK_PREINSTALL
  ${If} $INSTDIR != "$PROGRAMFILES64\${PRODUCTNAME}"
    MessageBox MB_OK|MB_ICONSTOP "ByteBroom installs only into $PROGRAMFILES64\${PRODUCTNAME}, a folder only administrators can change. Nothing was installed." /SD IDOK
    Abort
  ${EndIf}
!macroend
