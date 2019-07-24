rule EngWUltimate {
        meta:
                author = "jeFF0Falltrades"
                hash = "953b1b99bb5557fe86b3525f28f60d78ab16d56e9c3b4bbe75aba880f18cb6ad"

        strings:
                $b64_1 = "ZG8gbm90IHNjcmlwdA==" wide ascii // do not script
                $b64_2 = "Q2xpcEJvYXJkIExvZw==" wide ascii // ClipBoard Log
                $b64_3 = "RW5nIFdpe" wide ascii // Eng Wiz
                $b64_4 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25c" wide ascii // HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\
                $b64_5 = "Q3JNb2RNbmdy" wide ascii // CrModMngr
                $b64_6= "JVBER" wide ascii // Embedded data
                $b64_7 = "qQAAMAAAAEAAAA" wide ascii // Embedded data
                $str_1 = "Eng Wiz" wide ascii nocase
                $str_2 = "Engr Whizzy" wide ascii nocase
                $str_3 = "ClipBoard Log" wide ascii 
                $str_4 = "Keylogger Log" wide ascii 
                $str_pdb = "C:\\Users\\USER\\AppData\\Roaming\\System\\jobs" wide ascii nocase
                // ᚰᚣᛓᚦᚸᚸ᚜ᚨᚻᚼᚱᚻ --> decodes to SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu --> decodes to HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
                $hex_reg = { b0 16 a3 16 d3 16 a6 16 b8 16 b8 16 9c 16 a8 16 bb 16 bc 16 b1 16 bb 16 } 
                // MD5 hashing func
                $hex_md5_func = { 73 46 01 00 0A 0A 28 30 01 00 0A 02 6F 98 00 00 0A 0B 1F ?? 28 7D 00 00 0A } 

        condition:
                uint16(0) == 0x5A4D and ((3 of ($b64*)) or (3 of ($str*)) or (any of ($hex*)))
}