rule micropsia_2018 {
 meta:
    author = "jeFF0Falltrades"
    hash = "4c3fecea99a469a6daf2899cefe93d9acfd28a0b6c196592da47e917c53c2c76"

 strings:
    $gen_app_id = { 53 31 DB 69 93 08 D0 68 00 05 84 08 08 42 89 93 08 D0 68 00 F7 E2 89 D0 5B C3 } // 0x4072f0 loop which generates the unique "App ID"
    $get_temp_dir = { 68 00 04 00 00 8d 44 24 04 50 8b c7 e8 [4] 8b e8 55 e8 [2] fe ff } // 0x0042C689 func retrieving %TEMP%
    $str_install_appid = "ApppID.txt" wide ascii nocase

 condition:
    2 of them
}
