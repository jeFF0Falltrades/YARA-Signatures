import "pe"

// Fires on discovered MegaCortex samples using certificate signatures
rule megacortex_payload {
    meta:
        author = "jeFF0Falltrades"
        reference = "https://news.sophos.com/en-us/2019/05/03/megacortex-ransomware-wants-to-be-the-one/"

    condition:
        uint16(0) == 0x5a4d and ((for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b" or pe.signatures[i].serial == "71:a0:b7:36:95:dd:b1:af:c2:3b:2b:9a:18:ee:54:cb" or pe.signatures[i].serial == "5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc")) or pe.imphash() == "81da9241b26f498f1f7a1123ab76bb9d" or pe.imphash() == "ac3a9bb6fa7b3e8b91bfebe68b0d501b" or pe.imphash() == "17c56ef351018d9d9dabf0025a0394ac")
}

// Fires on the batch file used to stop AV/other services running prior to executing the MegaCortex payload (NOTE: May not be exclusive to MegaCortex)
rule megacortex_av_bat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_1 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_2 = "net stop SQLAgent$SOPHOS /ynet stop AVP /y"
        $str_3 = "net stop \"Sophos Clean Service\" /y"
        $str_4 = "net stop \"Sophos Device Control Service\" /y"
        $str_5 = "net stop \"Sophos File Scanner Service\" /y"
        $str_6 = "net stop \"Sophos Health Service\" /y"
        $str_7 = "net stop \"Sophos MCS Agent\" /y"
        $str_8 = "net stop \"Sophos MCS Client\" /y"
        $str_9 = "net stop \"Sophos Message Router\" /y"
        $str_10 = "net stop \"Sophos Safestore Service\" /y"
        $str_11 = "net stop \"Sophos System Protection Service\" /y"
        $str_12 = "net stop \"Sophos Web Control Service\" /y"
        $str_13 = "sc config VeeamHvIntegrationSvc start= disabled"
        $str_14 = "sc config MSSQL$VEEAMSQL2012 start"
        $str_15 = "sc config SQLAgent$CXDB start= disabled"
        $str_16 = "taskkill /IM zoolz.exe /F"
        $str_17 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_18 = "taskkill /IM wordpad.exe /F"
        $str_19 = "taskkill /IM xfssvccon.exe /F"
        $str_20 = "taskkill /IM tmlisten.exe /F"
        $str_21 = "taskkill /IM PccNTMon.exe /F"
        $str_22 = "taskkill /IM CNTAoSMgr.exe /F"
        $str_23 = "taskkill /IM Ntrtscan.exe /F"
        $str_24 = "taskkill /IM mbamtray.exe /F"
        $str_25 = "iisreset /stop"

    condition:
        5 of them
}

// Fires on the ransom note left behind MegaCortex ("!!!_READ_ME_!!!.txt")
rule megacortex_ransom {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $megacortex = "corrupted with MegaCortex" nocase
        $tsv = ".tsv"
        $morpheus = "We can only show you the door"
        $files = "email to us 2 files from random computers"
        $email_1 = "shawhart1542925@mail.com"
        $email_2 = "anderssperry6654818@mail.com"
        $email_3 = "ezequielgramlich6204294@mail.com"
        $email_4 = "cammostyn9012404@mail.com"

    condition:
        2 of them
}

// (WIP) Fires on meterpreter payloads found beaconing to a C2 discovered in the MegaCortex attacks (89[.]105[.]198[.]28)
rule megacortex_meterpreter {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "Bud. 120-A, Vul. Balkivska1"

    condition:
        uint16(0) == 0x5a4d and $cert and (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "00:CA:0E:70:90:D4:82:70:04:C9:9A:F2:FC:7D:73:3C:02" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D" or pe.signatures[i].serial == "03:01:9A:02:3A:FF:58:B1:6B:D6:D5:EA:E6:17:F0:66" or pe.signatures[i].serial == "06:FD:F9:03:96:03:AD:EA:00:0A:EB:3F:27:BB:BA:1B" or pe.signatures[i].serial == "0C:E7:E0:E5:17:D8:46:FE:8F:E5:60:FC:1B:F0:30:39"))
}

// (WIP) Fires on Rietspoof samples found loading MegaCortex based on certificates (
rule megacortex_rietspoof {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $cert = "8 Quarles Park Road1"
    
    condition:
         uint16(0) == 0x5a4d and ($cert or (for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial == "53:CC:4C:69:E5:6A:7D:BC:36:67:D5:FF:D5:24:AA:4B" or pe.signatures[i].serial == "1D:A2:48:30:6F:9B:26:18:D0:82:E0:96:7D:33:D3:6A" or pe.signatures[i].serial == "13:EA:28:70:5B:F4:EC:ED:0C:36:63:09:80:61:43:36" or pe.signatures[i].serial == "0E:CF:F4:38:C8:FE:BF:35:6E:04:D8:6A:98:1B:1A:50" or pe.signatures[i].serial == "7E:93:EB:FB:7C:C6:4E:59:EA:4B:9A:77:D4:06:FC:3B" or pe.signatures[i].serial == "00:AD:72:9A:65:F1:78:47:AC:B8:F8:49:6A:76:80:FF:1E" or pe.signatures[i].serial == "01:FD:6D:30:FC:A3:CA:51:A8:1B:BC:64:0E:35:03:2D")))
}