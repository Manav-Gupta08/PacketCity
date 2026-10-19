; PacketCity NSIS hooks. Npcap cannot be redistributed with the app (its free licence forbids it),
; so the installer only checks for it and points the user at the official download.
; Without Npcap the app still runs: demo mode and PCAP replay work, live capture is disabled.

!macro NSIS_HOOK_POSTINSTALL
  ReadRegStr $0 HKLM "SOFTWARE\Npcap" ""
  ${If} $0 == ""
    ${IfNot} ${FileExists} "$SYSDIR\Npcap\wpcap.dll"
      MessageBox MB_YESNO|MB_ICONINFORMATION "PacketCity needs the Npcap driver for live capture.$\r$\n$\r$\nDemo mode and PCAP replay work without it.$\r$\n$\r$\nOpen the official Npcap download page now?" /SD IDNO IDNO +2
        ExecShell "open" "https://npcap.com/#download"
    ${EndIf}
  ${EndIf}
!macroend
