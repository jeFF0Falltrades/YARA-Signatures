rule lockergoga {
   meta:
      author = "jeFF0Falltrades"
      hash = "bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f"

   strings:
      $dinkum = "licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED" wide ascii nocase
      $ransom_1 = "You should be thankful that the flaw was exploited by serious people and not some rookies." wide ascii nocase
      $ransom_2 = "Your files are encrypted with the strongest military algorithms RSA4096 and AES-256" wide ascii nocase
      $str_1 = "(readme-now" wide ascii nocase
      $mlcrosoft = "Mlcrosoft" wide ascii nocase
      $mutex_1 = "MX-tgytutrc" wide ascii nocase
      $cert_1 = "16 Australia Road Chickerell" wide ascii nocase
      $cert_2 = {  2E 7C 87 CC 0E 93 4A 52 FE 94 FD 1C B7 CD 34 AF } //  MIKL LIMITED
      $cert_3 = { 3D 25 80 E8 95 26 F7 85 2B 57 06 54 EF D9 A8 BF } // CCOMODO RSA Code Signing CA
      $cert_4 = {  4C AA F9 CA DB 63 6F E0 1F F7 4E D8 5B 03 86 9D } //  COMODO SECURE

   condition:
      4 of them
}
