import "pe"

rule nanocore_rat {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_nano_1 = "NanoCore.ClientPlugin" wide ascii
        $str_nano_2 = "NanoCore.ClientPluginHost" wide ascii
        $str_plg_1 = "Plugin [{0}] requires an update" wide ascii
        $str_plg_2 = "Plugin [{0}] is being uninstalled" wide ascii
        $str_conn_1 = "PrimaryConnectionHost" wide ascii
        $str_conn_2 = "BackupConnectionHost" wide ascii
        $str_id = "C8AA-4E06-9D54-CF406F661572" wide ascii
        // Loop used to load in config
        $load_config = { 02 06 9A 74 54 00 00 01 0B 02 06 17 58 9A 28 3A 00 00 0A }
    
    condition:
        2 of ($str_*) or $load_config or (pe.timestamp == 1424566177)
}

rule nanocore_surveillance_plugin {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_name = "SurveillanceExClientPlugin.dll" wide ascii
        $str_keylog = "KeyboardLogging" wide ascii
        $str_dns_log = "DNSLogging" wide ascii
        $str_html_1 = "<td bgcolor=#FFFFF0 nowrap>.+?<td bgcolor=#FFFCF0 nowrap>(.+?)<td bgcolor=#FFFAF0 nowrap>(.+?)<td bgcolor=#FFF7F0 nowrap>.+?<td bgcolor=#FFF5F0 nowrap>.+?<td bgcolor=#FFF2F0 nowrap>.+?<td bgcolor=#FFF0F0 nowrap>.+?<td bgcolor=#FCF0F2 nowrap>.+?<td bgcolor=#FAF0F5 nowrap>(.+?)<td bgcolor=#F7F0F7 nowrap>" wide ascii
        $str_html_2 = "<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>" wide ascii
        $str_html_3 = "/shtml \"{0}\"" wide ascii
        $str_rsrc_lzma = "Lzma" wide ascii
        $str_nano = "NanoCore.ClientPlugin" wide ascii
        $str_pass_tool = "ExecutePasswordTool" wide ascii
        $get_raw_input = { 20 03 00 00 10 12 02 12 04 02 7B 09 00 00 04 28 C8 00 00 06 } // GetRawInputData Loop
        $get_dns_cache = { 12 02 7B 62 00 00 04 7E 7F 00 00 0A 28 80 00 00 0A 2C B5 }   // GetDNSCacheDataTable Loop    
    
    condition:
        (all of ($get_*)) or (3 of ($str_*)) or (pe.timestamp == 1424566189)
}
