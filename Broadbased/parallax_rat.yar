rule parallax_rat_2020 {
  meta:
    author = "jeFF0Falltrades"
    
  strings:
    $str_ws = ".DeleteFile(Wscript.ScriptFullName)" wide ascii
    $str_cb_1 = "Clipboard Start" wide ascii
    $str_cb_2 = "Clipboard End" wide ascii
    $str_un = "UN.vbs" wide ascii
    $hex_keylogger = { 64 24 ?? C0 CA FA }

  condition:
    3 of them
}
