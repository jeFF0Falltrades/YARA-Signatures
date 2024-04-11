rule dcrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $venom_1 = "VenomRAT" wide ascii nocase
        $venom_2 = "HVNC_REPLY_MESSAGE" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_b64_amsi = "YW1zaS5kbGw=" wide ascii
        $str_b64_virtual_protect = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $str_dcrat = "dcrat" wide ascii nocase
        $str_plugin = "save_Plugin" wide ascii
        $str_qwqdan = "qwqdan" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        (not any of ($venom*)) and 5 of them and #patt_config >= 10
 }
