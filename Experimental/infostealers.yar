rule infostealer_xor_patterns {
  meta:
    author = "jeFF0Falltrades"
    hash = "d5d1d28270adc1588cf6be33a876587a3c689f6a51ea797eae6b64b5b15805b1"
    description = "The XOR and string patterns shown here appear to be unique to certain information-stealing malware families, namely LokiBot and Pony/Fareit. The XOR patterns were observed in a several loaders and payloads for LokiBot, but have also appeared (less frequently) in Pony/Fareit loaders and samples. The two accompanying rules below can be used to further classify the final payloads."

  strings:
        // call dword ptr ds:[<&GetLastInputInfo>]; sub eax,edi; cmp eax,143
        // User input check in first stage loader (anti-VM)
        $hx_get_input = { ff 15 58 7f 47 00 a1 60 7f 47 00 2b c7 3d 43 01 00 00 }

        // xor byte ptr ds:[ecx],45; inc dword ptr ss:[ebp-4]; cmp dword ptr ss:[ebp-4],5E07
        // XOR loop in first stage loader to decrypt the second stage loader
        $hx_xor_1 = { 80 31 45 FF 45 FC 81 7D FC 07 5E 00 00 }

        // ($hx_xor_3 ^ 0x45)
        // Second stage loader XOR loop pattern as it is stored in first stage loader prior to being XOR'd
        $hx_xor_2 = { c8 51 44 c6 a7 4a cf 51 7f 75 55 05 }

        // lea edx,dword ptr ds:[ecx+eax]; and edx,F; mov dl,byte ptr ds:[edx+edi]; xor byte ptr ds:[eax],dl; inc eax
        // This is ($hx_xor_2 ^ 0x45), found in the second stage loader stub after being XOR'd by the first stage loader
        $hx_xor_3 = { 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 }

        // xor ecx,0x4358ad54; shr ecx,1;  dec eax
        // XOR loop found in final payload
        $hx_xor_4 = { 81 F1 54 AD 58 43 D1 E9 48 }

  condition:
    $hx_xor_4 or 2 of them
}

// Strings common to LokiBot
rule infostealer_loki {
  strings:
        $str_builder = "fuckav.ru" nocase wide ascii
        $str_cyb_fox = "%s\\8pecxstudios\\Cyberfox\\profiles.ini" wide ascii
        $str_c2 = "fre.php" wide ascii

  condition:
    any of them and infostealer_xor_patterns
}

// Strings common to Pony
rule infostealer_pony {
  strings:
        $str_softx = "Software\\SoftX.org\\FTPClient\\Sites" wide ascii
        $str_ftp_plus = "FTP++.Link\\shell\\open\\command" wide ascii
        $str_c2 = "gate.php" wide ascii

  condition:
    any of them and infostealer_xor_patterns
}
