rule kleptoparasite {
 meta:
     author = "jarcher"
     hash = "2109fdb52f63a8821a7f3efcc35fa36e759fe8b57db82aa9b567254b8fb03fb1"
 
 strings:
     $str_full_pdb = "E:\\Work\\HF\\KleptoParasite Stealer 2018\\Version 3\\3 - 64 bit firefox n chrome\\x64\\Release\\Win32Project1.pdb" wide ascii nocase
     $str_part_pdb_1 = "KleptoParasite" wide ascii nocase
     $str_part_pdb_2 = "firefox n chrome" wide ascii nocase
     $str_sql= "SELECT origin_url, username_value, password_value FROM logins" wide ascii nocase
     $str_chrome_32 = "<center>Google Chrome 32bit NOT INSTALLED" wide ascii nocase
     $str_firefox_32 = "<center>FireFox 32bit NOT INSTALLED" wide ascii nocase
     $str_chrome_64 = "<center>Google Chrome 64bit NOT INSTALLED" wide ascii nocase
     $str_firefox_64 = "<center>FireFox 64bit NOT INSTALLED" wide ascii nocase
     $str_outlook_32 = "Microsoft Outlook 32 bit</b>" wide ascii nocase
     $str_outlook_64 = "Microsoft Outlook 64 bit</b>" wide ascii nocase
     $str_outlook_prof = "Outlook\\Profiles\\Outlook\\" wide ascii
     $str_obf = "naturaleftouterightfullinnercross" wide ascii nocase
     $str_c2 = "ftp.totallyanonymous.com" wide ascii nocase
     $str_fn = "fc64.exe" wide ascii nocase
     $str_ip = "myexternalip.com/raw" wide ascii
     $str_ret = "IP retriever" wide ascii
     $str_dxwrk = "DXWRK.html" wide ascii
    
 condition:
     3 of them
}
