rule ave_maria_warzone_rat {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://blog.team-cymru.com/2019/07/25/unmasking-ave_maria/"

  strings:
    $str_0 = "5.206.225.104/dll/" wide ascii
    $str_1 = "AVE_MARIA" wide ascii 
    $str_2 = "MortyCrypter\\MsgBox.exe" wide ascii 
    $str_3 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q" wide ascii 
    $str_4 = "ellocnak.xml" wide ascii 
    $str_5 = "Hey I'm Admin" wide ascii 
    $str_6 = "AWM_FIND" wide ascii 
    $str_7 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide ascii 
    $str_8 = "warzone" wide ascii 

  condition:
  	3 of them
}
