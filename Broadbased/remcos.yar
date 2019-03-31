import "pe"

rule remcos_dropper {
 meta:
     author = "jeFF0Falltrades"
     hash = "66f695df85e48468a4e33700d70a406ac052ef44aa8b2e98093905d8e7fc2b6c"

 strings:
     $str_upload = "Uploading file to C&C" wide ascii nocase
     $str_keylog_1 = "Offline Keylogger Started" wide ascii nocase
     $str_keylog_2 = "Online Keylogger Started" wide ascii nocase
     $str_mutex_1 = "Mutex_RemWatchdog" wide ascii nocase
     $str_mutex_2 = "Remcos_Mutex_Inj" wide ascii nocase
     $str_cleared = "Cleared all cookies & stored logins!" wide ascii nocase
     $str_bs_vendor = "Breaking-Security.Net" wide ascii nocase
     $str_controller = "Connecting to Controller..." wide ascii nocase
     $str_c2 = "duckdns.org" wide ascii nocase
	 $str_excp = { 8B 7D 08 57 8B 3F } //  mov edi, [ebp+arg_0]; push edi; mov edi, [edi] (anti-debug --> KiUserExceptionDispatcher)

 condition:
     3 of ($str*) or (pe.sections[0].name == "VVR" and pe.sections[1].name == "ZKZR" and pe.sections[2].name == ".test" and pe.sections[3].name == "rca" and pe.sections[4].name == "vga")
}
