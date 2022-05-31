rule redline_dropper {
	meta:
		author = "jeFF0Falltrades"
		hash = "6d477b08a0b9c1e8db4ecb921d07b124973f5213639d88fff7df5146adcefc79"
		description = "This rule matches droppers that appear to be related to samples of RedLine Stealer or a derivation (as of APR2021)"

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

rule redline_stealer {
	meta:
		author = "jeFF0Falltrades"
		hash = "f64ed3bd7304cdec6e99bb35662aa485e32156c1ca7275fed0c1e67d2f9fc139"
		description = "This rule matches unpacked RedLine Stealer samples and derivatives (as of APR2021)"

	strings:
		$str_0 = "Software\\Valve\\SteamLogin Data" wide ascii
		$str_1 = "name_on_cardencrypted_value" wide ascii
		$str_2 = "card_number_encrypted" wide ascii
		$str_3 = "geoplugin_region!" wide ascii
		$str_4 = "set_GameChatFiles" wide ascii
		$str_5 = "set_ScanDiscord" wide ascii
		$str_6 = "<GameChatFiles>k__BackingField" wide ascii

	condition:
		3 of them
}
