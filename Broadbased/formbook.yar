// Fires on Formbook VB6 initial and extracted files
rule formbook_vb {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://thisissecurity.stormshield.com/2018/03/29/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/"

    strings:
        $hex_set_info = { 68 65 73 73 00 68 50 72 6F 63 68 74 69 6F 6E 68 6F 72 6D 61 68 74 49 6E 66 68 4E 74 53 65 54 EB 2C }
        $hex_decode_loop = { 81 34 24 [4] 83 E9 03 E0 F1 FF 34 0E 81 34 24 }
        $hex_anti_check = { 80 78 2A 00 74 3D 80 78 2B 00 74 37 80 78 2C 00 75 31 80 78 2D 00 75 2B 80 78 2E 00 74 25 80 78 2F 00 75 1F 80 78 30 00 74 19 80 78 31 00 75 13 80 78 32 00 74 0D 80 78 33 00 }
        $hex_precheck = { E8 AE FA FF FF 3D 00 03 00 00 0F 9F C2 56 88 56 35 E8 3D FC FF FF 56 E8 E7 F6 FF FF 56 E8 41 F9 FF FF 56 E8 AB F7 FF FF 56 E8 F5 DE FF FF }
        $str_marker = "r5.oZe/gg" wide ascii

    condition:
        2 of them
}
