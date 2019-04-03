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
    /* The final portion of this condition looks for the ZIP archive footer within 25 bytes of the end of the file - This can be omitted or adjusted for your use case. */
    (for any of ($img*): ($ at 0)) and (all of ($zip*)) and ($zip_footer in (filesize-25..filesize))
}
