import "pe"

rule remcos_rat {
 meta:
     author = "jeFF0Falltrades"
 
 strings:
     $str_upload = "Uploading file to C&C" wide ascii
     $str_keylog_1 = "Offline Keylogger Started" wide ascii
     $str_keylog_2 = "Online Keylogger Started" wide ascii
     $str_mutex_1 = "Mutex_RemWatchdog" wide ascii
     $str_mutex_2 = "Remcos_Mutex_Inj" wide ascii
     $str_cleared = "Cleared all cookies & stored logins!" wide ascii
     $str_bs_vendor = "Breaking-Security.Net" wide ascii
     $str_controller = "Connecting to Controller..." wide ascii
     $str_rc4 = { 40 8b cb 99 f7 f9 8b 84 95 f8 fb ff ff 8b f3 03 45 fc 89 55 f8 8d 8c 95 f8 fb ff ff 99 f7 fe 8a 01 8b f2 8b 94 b5 f8 fb ff ff } // RC4 PRGA

 condition:
     3 of ($str*) or (pe.sections[0].name == "VVR" and pe.sections[1].name == "ZKZR" and pe.sections[2].name == ".test" and pe.sections[3].name == "rca" and pe.sections[4].name == "vga")
}
