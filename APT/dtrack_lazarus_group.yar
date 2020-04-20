rule dtrack_2020 {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $pdb = "Users\\user\\Documents\\Visual Studio 2008\\Projects\\MyStub\\Release\\MyStub.pdb" wide ascii
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $str_tmp = "%s\\~%d.tmp" wide ascii
        $str_exc = "Execute_%s.log" wide ascii
        $str_reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $str_reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/
        $hex_1 = { d1 ?? 33 ?? fc 81 ?? ff 00 00 00 c1 ?? 17 }
        $hex_2 = { c1 ?? 08 8b ?? fc c1 ?? 10 }
        $hex_3 = { 81 0D [4] 1C 31 39 29 }
    condition:
        2 of them or $hex_3
}
