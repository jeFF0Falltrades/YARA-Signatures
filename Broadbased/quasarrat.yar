rule quasarrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_quasar = "Quasar." wide ascii
        $str_hidden = "set_Hidden" wide ascii
        $str_shell = "DoShellExecuteResponse" wide ascii
	$str_close = "echo DONT CLOSE THIS WINDOW!" wide ascii
        $str_pause = "ping -n 10 localhost > nul" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 25 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $byte_special_folder = { 7e 73 [4] 28 [4] 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        6 of them and #patt_config >= 10
 }
