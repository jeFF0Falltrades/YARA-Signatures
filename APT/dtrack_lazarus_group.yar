rule dtrack_2019 {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://usa.kaspersky.com/about/press-releases/2019_dtrack-previously-unknown-spy-tool-hits-financial-institutions-and-research-centers"

    strings:
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_conn = "=================== Connection Status ===================" wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/

    condition:
        2 of them
}
