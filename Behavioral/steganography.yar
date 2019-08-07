
rule zip_img_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule attempts to identify ZIP (and JAR, APK, DOCX, etc.) archives embedded within various image filetypes."

  strings:
    $img_gif = { 47 49 46 38 }
    $img_jpeg_1 = { FF D8 FF DB } // explicitly break out JPEG variations to avoid triggering a "slowing down scanning" condition
    $img_jpeg_2 = { FF D8 FF E0 }
    $img_jpeg_3 = { FF D8 FF EE }
    $img_jpeg_4 = { FF D8 FF E1 }
    $img_png = { 89 50 4E 47 0D 0A 1A 0A }
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    /* The final portion of this condition looks for the ZIP archive footer within 25 bytes
    of the end of the file - This can be omitted or adjusted for your use case, but appears 
    to work for several waves of infostealers seen at the time of writing. */
    (for any of ($img*): ($ at 0)) and (all of ($zip*)) and ($zip_footer in (filesize-25..filesize))
}

rule zip_iso_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule identifies a specific phishing technique of sending ISO file attachments containing ZIP (and JAR, APK, DOCX, etc.) archives which in turn contain malicious executables."

  strings:
    $iso_header = { 43 44 30 30 31 } // CD001
    $exe_zip = { 2e 65 78 65 50 4b 05 06 00 00 00 00 01 00 01 } // .exePK signature

  condition:
    (($iso_header at 0x8001) or ($iso_header at 0x8801) or ($iso_header at 0x9001)) and $exe_zip
}

rule lokibot_img_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule identifies a specific variant of LokiBot which uses image steganography to obscure an encrypted payload; See reference."
    reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/lokibot-gains-new-persistence-mechanism-uses-steganography-to-hide-its-tracks/"

  strings:
    $img_gif = { 47 49 46 38 }
    $img_jpeg_1 = { FF D8 FF DB } // explicitly break out JPEG variations to avoid triggering a "slowing down scanning" condition
    $img_jpeg_2 = { FF D8 FF E0 }
    $img_jpeg_3 = { FF D8 FF EE }
    $img_jpeg_4 = { FF D8 FF E1 }
    $img_png = { 89 50 4E 47 0D 0A 1A 0A }
    $loki_enc_header = { 23 24 25 5e 26 2a 28 29 5f 5f 23 40 24 23 35 37 24 23 21 40 }

  condition:
    (for any of ($img*): ($ at 0)) and $loki_enc_header
}