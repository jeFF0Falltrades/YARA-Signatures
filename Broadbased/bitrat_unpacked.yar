rule bitrat_unpacked
{
    meta:
        author = "jeFF0Falltrades"
        hash = "122cd4f33d1e1b42ce0d959bc35e5d633b029f4869c5510624342b5cc5875c98"
        description = "Experimental rule to detect unpacked BitRat payloads on disk or in memory, looking for a combination of strings and decryption/decoding patterns"
        reference = "https://krabsonsecurity.com/2020/08/22/bitrat-the-latest-in-copy-pasted-malware-by-incompetent-developers/"

    strings:
        $str_0 = "string too long" wide ascii
        $str_1 = "invalid string position" wide ascii
        $hex_0 = { 6b ?? 25 99 f7 ?? 8d [2] 99 f7 }
        $hex_1 = { 0f ba 25 [3] 00 01 0f 82 [4] 0f ba 25 [3] 00 00 }
        $hex_2 = { 66 0f 6f ?? 66 0f 6f [2] 66 0f 6f [2] 66 0f 6f [2] 66 0f 7f ?? 66 0f 7f [2] 66 0f 7f [2]  66 0f 7f  }
        $hex_3= { 8b [2] d3 ?? 33 05 }
        $hex_4 = { 83 [2] 00 c7 05 [8] c7 05 [8] c7 05 [8] 83 }

    condition:
        6 of them
}
