rule venomrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_id_venomrat = "venomrat" wide ascii nocase
        $str_hvnc = "HVNC_REPLY_MESSAGE" wide ascii
        $str_offline_keylogger = "OfflineKeylog sending...." wide ascii
        $str_videocontroller = "select * from Win32_VideoController" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_keylog = {73 [3] 06 80 [3] 04}
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        5 of them and #patt_config >= 10
 }
