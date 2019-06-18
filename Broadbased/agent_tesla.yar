rule agent_tesla_2019 {
    meta:
        author = "jeFF0Falltrades"
        hash = "717f605727d21a930737e9f649d8cf5d12dbd1991531eaf68bb58990d3f57c05"

    strings:
        $appstr_1 = "Postbox" wide ascii nocase
        $appstr_2 = "Thunderbird" wide ascii nocase
        $appstr_3 = "SeaMonkey" wide ascii nocase
        $appstr_4 = "Flock" wide ascii nocase
        $appstr_5 = "BlackHawk" wide ascii nocase
        $appstr_6 = "CyberFox" wide ascii nocase
        $appstr_7 = "KMeleon" wide ascii nocase
        $appstr_8 = "IceCat" wide ascii nocase
        $appstr_9 = "PaleMoon" wide ascii nocase
        $appstr_10 = "IceDragon" wide ascii nocase
        // XOR sequence used in several decoding sequences in final payload
        $xor_seq = { FE 0C 0E 00 20 [4] 5A 20 [4] 61 } 

    condition:
        all of them and #xor_seq > 10
}