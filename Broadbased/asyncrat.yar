rule asyncrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $val_async = "AsyncClient" wide ascii nocase
        $val_schtasks = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide ascii
        $val_pong = "ActivatePong" wide ascii
        $val_ext = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide ascii
        $aes_exc = "masterKey can not be null or empty" wide ascii
        $aes_salt = { BF EB 1E 56 FB CD 97 3B B2 19 24 30 A5 78 43 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41 }
        $patt_aes = { 6F [4] 80 ?? 00 00 04 7E ?? 00 00 04 73 }
        $patt_settings = { 72 [2] 00 70 80 [2] 00 04 }

    condition:
        5 of them or (2 of ($val*) and 1 of ($aes*)) or (4 of them and #patt_settings >= 15)
}