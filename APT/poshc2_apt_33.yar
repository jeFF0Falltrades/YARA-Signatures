rule poshc2_apt_33_2019 {
    meta:
        author = "jeFF0Falltrades"
        desc = "Alerts on PoshC2 payloads which align with 2019 APT33 reporting (this will not fire on all PoshC2 payloads)"
        ref = "http://www.rewterz.com/rewterz-news/rewterz-threat-alert-iranian-apt-uses-job-scams-to-lure-targets"
    
    strings:
        $js_date = /\[datetime\]::ParseExact\("[0-9]+\/[0-9]+\/[0-9]+","dd\/MM\/yyyy",\$null/
        $js_crypt = "System.Security.Cryptography" wide ascii
        $js_host = "Headers.Add(\"Host" wide ascii
        $js_proxy = "$proxyurl = " wide ascii
        $js_arch = "$env:PROCESSOR_ARCHITECTURE" wide ascii
        $js_admin = "[System.Security.Principal.WindowsBuiltInRole]::Administrator" wide ascii
        $hta_unescape = "%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%27%3c%73%63%72%69%70%74%20%74%79%70%65%3d%22%74%65%78%74%2f%76%62%73%63%72%69%70%74%22%3e%5c%6e%53%75%62%20%41%75%74%6f%4f%70%65%6e%28%29" wide ascii
        $hta_hex = "202f7720312049455820284e65772d4f626a656374204e65742e576562436c69656e74292e446f776e6c6f6164537472696e672827687474703a2f2f352e3235322e3137382e32302f7261797468656f6e322d6a6f62732e6a706727293b" wide ascii
        $hta_powershell = "706f7765727368656c6c2e657865" wide ascii

    condition:
        4 of ($js_*) or 2 of ($hta_*)
}
