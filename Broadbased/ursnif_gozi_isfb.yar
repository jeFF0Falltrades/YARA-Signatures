rule ursnif_zip_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $doc_name = { 69 6e 66 6f 5f ?? ?? 2e ?? ?? 2e 64 6f 63 } // info_MM.DD.doc
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    ($zip_header at 0) and ($doc_name in (0..48)) and ($zip_footer in (filesize-150..filesize))
}

rule ursnif_dropper_doc_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $sleep = "WScript.Sleep(56000)" wide ascii nocase
    $js = ".js" wide ascii
    $ret = { 72 65 74 75 72 6e 20 22 52 75 22 20 2b 20 22 5c 78 36 65 22 } // return "Ru" + "\x6e"
    $pse = { 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 20 } //powershell -Enc

  condition:
    uint16(0) == 0xcfd0 and all of them
}