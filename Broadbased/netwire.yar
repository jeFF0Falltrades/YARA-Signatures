rule netwire {
  meta:
    author = "jeFF0Falltrades"
    hash = "80214c506a6c1fd8b8cd2cd80f8abddf6b771a4b5808a06636b6264338945a7d"

  strings:
    $ping = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" wide ascii nocase
    $bat_1 = "DEL /s \"%s\" >nul 2>&1" wide ascii nocase
    $bat_2 = "call :deleteSelf&exit /b" wide ascii nocase
    $bat_3 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" wide ascii nocase
    $ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii nocase
    $log = "[Log Started]" wide ascii nocase
    $xor = { 0F B6 00 83 F0 ?? 83 C0 ?? 88 02 } // movzx eax, byte ptr [eax]; xor eax, ??; add  eax, ??;  mov [edx], al (XOR encryption of log data)

  condition:
    4 of them
}
