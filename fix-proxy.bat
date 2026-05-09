@echo off
echo [*] Restaurare conexiune directa la internet...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
echo [+] Proxy dezactivat.

powershell -NonInteractive -ExecutionPolicy Bypass -Command ^
  "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class WI{[DllImport(\"wininet.dll\")]public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l);}'; [WI]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;[WI]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null"
echo [+] Chrome/Edge notificate.
echo.
echo Internetul functioneaza acum normal.
pause
