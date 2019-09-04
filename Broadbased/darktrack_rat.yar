import "pe"

rule darktrack_rat {
    meta:
        author = "jeFF0Falltrades"
        hash = "1472dd3f96a7127a110918072ace40f7ea7c2d64b95971e447ba3dc0b58f2e6a"
        ref = "https://news.softpedia.com/news/free-darktrack-rat-has-the-potential-of-being-the-best-rat-on-the-market-508179.shtml"

    strings:
        $dt_pdb = "C:\\Users\\gurkanarkas\\Desktop\\Dtback\\AlienEdition\\Server\\SuperObject.pas" wide ascii
        $dt_pas = "SuperObject.pas" wide ascii
        $dt_user = "].encryptedUsername" wide ascii
        $dt_pass = "].encryptedPassword" wide ascii
        $dt_yandex = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide ascii
        $dt_alien_0 = "4.0 Alien" wide ascii
        $dt_alien_1 = "4.1 Alien" wide ascii
        $dt_victim = "Local Victim" wide ascii

    condition:
        (3 of ($dt*)) or pe.imphash() == "ee46edf42cfbc2785a30bfb17f6da9c2" or pe.imphash() == "2dbff3ce210d5c2b4ba36c7170d04dc2"
}