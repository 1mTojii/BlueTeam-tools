#include "signatures.h"

/*
 * These are deliberately common, low-specificity indicators used across a
 * lot of introductory static analysis or malware triage tooling. Grouped
 * roughly by category like code execution, obfuscation orencoding, persistence
 * and living-off-the-land tools, and network or exfil indicators.
 */
const Signature SIGNATURES[] = {
    /* Code execution */
    {"eval(",              SEV_MEDIUM,   "Dynamic code execution"},
    {"exec(",               SEV_MEDIUM,   "Dynamic code execution"},
    {"system(",             SEV_MEDIUM,   "Shell command execution"},
    {"shell_exec(",         SEV_HIGH,     "PHP shell command execution"},
    {"passthru(",           SEV_HIGH,     "PHP command execution + output"},
    {"Invoke-Expression",   SEV_HIGH,     "PowerShell dynamic execution"},
    {"IEX(",                SEV_HIGH,     "PowerShell Invoke-Expression shorthand"},

    /* Obfuscation or encoding */
    {"base64_decode",       SEV_MEDIUM,   "Base64 decoding, common obfuscation step"},
    {"FromBase64String",    SEV_MEDIUM,   ".NET/PowerShell base64 decoding"},
    {"unescape(",           SEV_MEDIUM,   "JS string decoding, common in obfuscated payloads"},
    {"fromCharCode",        SEV_MEDIUM,   "JS char-code obfuscation"},
    {"-enc ",               SEV_HIGH,     "PowerShell encoded-command flag"},
    {"-EncodedCommand",     SEV_HIGH,     "PowerShell encoded-command flag"},
    {"certutil -decode",    SEV_HIGH,     "certutil abused for base64 decoding (LOLBin)"},

    /* Living-off-the-land or persistence */
    {"mshta",               SEV_HIGH,     "mshta.exe, common LOLBin for script execution"},
    {"regsvr32",            SEV_HIGH,     "regsvr32.exe, common LOLBin for DLL execution"},
    {"WScript.Shell",       SEV_MEDIUM,   "Windows Script Host shell object"},
    {"ActiveXObject",       SEV_MEDIUM,   "ActiveX object instantiation (common in malicious VBS/JS)"},
    {"CreateObject(",       SEV_LOW,      "COM object creation, common in scripts/macros"},
    {"AutoOpen",            SEV_MEDIUM,   "Office macro auto-run trigger"},
    {"Document_Open",       SEV_MEDIUM,   "Office macro auto-run trigger"},
    {"/bin/sh",             SEV_LOW,      "Shell invocation"},
    {"/bin/bash",           SEV_LOW,      "Shell invocation"},
    {"cmd.exe",             SEV_LOW,      "Windows command shell invocation"},

    /* Network or exfil indicators */
    {"curl -s",             SEV_LOW,      "Silent curl download, common in droppers"},
    {"wget -q",             SEV_LOW,      "Silent wget download, common in droppers"},
    {"Net.WebClient",       SEV_MEDIUM,   ".NET web client, common download-and-execute pattern"},
    {"DownloadString",      SEV_HIGH,     "PowerShell download-and-execute pattern"},
    {"DownloadFile(",       SEV_MEDIUM,   "Programmatic file download"},
};

const int SIGNATURE_COUNT = sizeof(SIGNATURES) / sizeof(SIGNATURES[0]);

const char *severity_to_string(Severity sev) {
    switch (sev) {
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}
