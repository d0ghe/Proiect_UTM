const fs   = require('fs');
const path = require('path');

const RULES_FILE = path.join(__dirname, 'yara-rules.yar');

const BUILTIN_RULES = `
rule Mimikatz_Strings {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Mimikatz credential dumper strings"
  strings:
    $a = "mimikatz"
    $b = "sekurlsa"
    $c = "lsadump"
    $d = "privilege::debug"
    $e = "kerberos::golden"
  condition:
    any of them
}

rule Metasploit_Meterpreter {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Metasploit Meterpreter payload indicators"
  strings:
    $a = "meterpreter"
    $b = "ReflectiveLoader"
    $c = { fc e8 82 00 00 00 }
    $d = "MSFPAYLOAD"
    $e = "msfvenom"
  condition:
    any of them
}

rule PowerShell_Encoded_Cradle {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "PowerShell encoded download cradle"
  strings:
    $a = "-EncodedCommand"
    $b = "-enc "
    $c = "IEX("
    $d = "Invoke-Expression"
    $e = "DownloadString"
    $f = "WebClient"
  condition:
    2 of them
}

rule Ransomware_Indicators {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Generic ransomware behavioral indicators"
  strings:
    $a = "YOUR FILES HAVE BEEN ENCRYPTED"
    $b = "send bitcoin"
    $c = "pay ransom"
    $d = "decrypt your files"
    $e = ".onion"
    $f = "CryptoLocker"
    $g = "WannaCry"
    $h = "WNCRY"
    $i = "bitcoin wallet"
  condition:
    any of ($a, $b, $c, $d) or 2 of ($e, $f, $g, $h, $i)
}

rule Cobalt_Strike {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Cobalt Strike beacon indicators"
  strings:
    $a = "cobaltstrike"
    $b = "beacon.dll"
    $c = "CS_SLEEP"
    $d = "beacon.x64.dll"
    $e = "pipe\\MSSE-"
    $f = "ReflectiveDll"
    $g = "beacon.x86.dll"
  condition:
    any of them
}

rule Keylogger_Indicators {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Keylogger / spyware indicators"
  strings:
    $a = "GetAsyncKeyState"
    $b = "SetWindowsHookEx"
    $c = "keylogger"
    $d = "WH_KEYBOARD_LL"
    $e = "keystrokes"
  condition:
    2 of them
}

rule Remote_Access_Tool {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Remote access trojan indicators"
  strings:
    $a = "njRAT"
    $b = "DarkComet"
    $c = "QuasarRAT"
    $d = "AsyncRAT"
    $e = "RemcosRAT"
    $f = "AgentTesla"
    $g = "NanoCore"
  condition:
    any of them
}

rule Shellcode_Loader {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Shellcode loader / injector patterns"
  strings:
    $a = "VirtualAlloc"
    $b = "CreateRemoteThread"
    $c = "WriteProcessMemory"
    $d = "NtUnmapViewOfSection"
    $e = "ZwCreateThreadEx"
  condition:
    3 of them
}

rule Office_Macro_Dropper {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Malicious Office macro dropper"
  strings:
    $a = "AutoOpen"
    $b = "Auto_Open"
    $c = "Shell("
    $d = "WScript.Shell"
    $e = "CreateObject"
    $f = "powershell"
  condition:
    ($a or $b) and 2 of ($c, $d, $e, $f)
}

rule Credential_Theft {
  meta:
    author = "U-Trust"
    severity = "critical"
    description = "Credential harvesting indicators"
  strings:
    $a = "password"
    $b = "credentials"
    $c = "NtlmHash"
    $d = "SAM database"
    $e = "DPAPI"
    $f = "CryptUnprotectData"
  condition:
    3 of them
}
`;

function getRulesText() {
  try {
    if (fs.existsSync(RULES_FILE)) {
      const custom = fs.readFileSync(RULES_FILE, 'utf8').trim();
      if (custom) return BUILTIN_RULES + '\n' + custom;
    }
  } catch { /* ignore */ }
  return BUILTIN_RULES;
}

function getCustomRulesText() {
  try {
    if (fs.existsSync(RULES_FILE)) return fs.readFileSync(RULES_FILE, 'utf8');
  } catch { /* ignore */ }
  return '';
}

function saveCustomRulesText(text) {
  fs.writeFileSync(RULES_FILE, String(text || ''), 'utf8');
}

function getBuiltinRules() {
  return BUILTIN_RULES;
}

module.exports = { getRulesText, getCustomRulesText, saveCustomRulesText, getBuiltinRules };
