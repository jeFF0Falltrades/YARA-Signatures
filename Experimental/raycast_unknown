rule raycast_unknown {
  meta:
    author = "jeFF0Falltrades"
    hash = "6d477b08a0b9c1e8db4ecb921d07b124973f5213639d88fff7df5146adcefc79"

  strings:
    $str_0 = "RayCastingCSHARP.Properties.Resources.resources" wide ascii
    $str_1 = "VOICEPHILIN" wide ascii
    $str_2 = "TRUECITY" wide ascii
    $str_3 = "Ronald RayGun" wide ascii
    $str_4 = "MR POLICE" wide ascii
    $hex_0 = { 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A }

  condition:
    2 of them
}
