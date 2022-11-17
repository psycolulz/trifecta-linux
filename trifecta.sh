#!/bin/bash
tput bold
welcome() {
    command clear
    echo
    echo "  _____ __ __   ___   __ __  ______       ___   __ __  ______  _____"
    echo " / ___/|  |  | /   \ |  |  ||      |     /   \ |  |  ||      |/ ___/"
    echo "(   \_ |  |  ||     ||  |  ||      |    |     ||  |  ||      (   \_ "
    echo " \__  ||  _  ||  O  ||  |  ||_|  |_|    |  O  ||  |  ||_|  |_|\__  |"
    echo " /  \ ||  |  ||     ||  :  |  |  |      |     ||  :  |  |  |  /  \ |"
    echo " \    ||  |  ||     ||     |  |  |      |     ||     |  |  |  \    |"
    echo "  \___||__|__| \___/  \__,_|  |__|       \___/  \__,_|  |__|   \___|"
    echo "======================================================================"
    echo "======================================================================"
    echo "Colleague/Friend --------------------------------------------- Ego"
    echo "Colleague/Friend ---------------------------------------------- Viking"
    echo "Co-Dev Of Search Section --------------------------------------- Vixx"
    echo "Colleague/Friend ---------------------------------------------- Crank"
    echo "Colleague/Friend ---------------------------------------------- Silky"
    echo "Colleague/Friend ---------------------------------------------- R."
    echo "Colleague/Friend ------------------------------------------- Balgogan"
    echo "======================================================================"
    echo "======================================================================"
    echo "1. Proceed To Main Menu"
    read -p $'Enter Option Here:' gotomain
    if [[ $gotomain == "1" ]]
    then
    main
    else 
    welcome
    fi                                                                   
}
main() {
    command clear
    echo
    echo " _______   _  __          _         "
    echo "|__   __| (_)/ _|        | |        "
    echo "   | |_ __ _| |_ ___  ___| |_ __ _  "
    echo "   | | ;__| |  _/ _ \/ __| __/ _: | "
    echo "   | | |  | | ||  __/ (__| || (_| | "
    echo "   |_|_|  |_|_| \___|\___|\__\__._| "   
    echo
    echo "Red Team Focused Framework For Linux - Based Off Of https://github.com/psycolulz/trifecta_public"
    echo
    echo "1  - Putty ===================="
    echo "2  - AnonSurf Tor Proxy ======="
    echo "3  - Tools By PsycoLulz ======="
    echo "4  - Learning Resources ======="
    echo "5  - Privacy =================="
    echo "6  - Vulnerability Scanning ==="
    echo "7  - OSINT Framework =========="
    echo "8  - Search ==================="
    echo "9  - Update Tool =============="
    read -p $'Enter Option Here:' choice
    if [[ $choice == "1" ]] 
    then
    puttysection
    elif [[ $choice == "2" ]] 
    then
    anonsurfsection
    elif [[ $choice == "3" ]] 
    then
    psycostoolbox
    elif [[ $choice == "4" ]] 
    then
    learningsources
    elif [[ $choice == "5" ]] 
    then
    privacy
    elif [[ $choice == "6" ]] 
    then
    vulnscanning
    elif [[ $choice == "7" ]] 
    then
    osintframeworksection
    elif [[ $choice == "8" ]] 
    then
    searchsection
    elif [[ $choice == "9" ]] 
    then
    updatesection
    else
    command clear 
    main
    fi
}
puttysection() {
    command clear
    echo
    echo "1. Install Putty"
    echo "2. Run Putty"
    echo "3. Back"
    echo
    read -p $'Enter Putty Option Here:' puttyoption
    if [[ $puttyoption == "1" ]] 
    then
    command sudo apt install putty
    elif [[ $puttyoption == "2" ]] 
    then
    command putty 
    elif [[ $puttyoption == "3" ]] 
    then
    main
    else
    command clear
    puttysection
    fi
}
anonsurfsection() {
    command clear
    echo
    echo "1. Install AnonSurf-Kali"
    echo "2. Run AnonSurf-Kali"
    echo "3. Stop AnonSurf-Kali"
    echo "4. Run AnonSurf Auto-Change"
    echo "5. Back"
    echo
    read -p $'Enter AnonSurf Option Here:' anonsurfoption
    if [[ $anonsurfoption == "1" ]] 
    then
    installanonsurf
    elif [[ $anonsurfoption == "2" ]] 
    then
    runanonsurf
    elif [[ $anonsurfoption == "3" ]]
    then
    stopanonsurf
    elif [[ $anonsurfoption == "4" ]] 
    then
    runautochange
    elif [[ $anonsurfoption == "5" ]] 
    then
    main 
    else
    command clear 
    anonsurfsection
    fi
}
installanonsurf() {
    command clear
    command git clone https://github.com/Und3rf10w/kali-anonsurf
    echo
    echo "Exit Tool, Type cd kali-anonsurf, and run installer.sh (must be run as root!)"
    sleep 40
    main
}
runanonsurf() {
    command clear
    command anonsurf start
    main
}
stopanonsurf() {
    command clear
    command anonsurf stop 
    main
}
runautochange(){
    command clear
    while true
    do
    echo
    echo  "____  ____ ___  _ ____  ____  _     _     _     ____" 
    echo "/  __\/ ___\\  \///   _\/  _ \/ \   / \ /\/ \   /_   \ "
    echo "|  \/||    \ \  / |  /  | / \|| |   | | ||| |    /   / "
    echo "|  __/\___ | / /  |  \_ | \_/|| |_/\| \_/|| |_/\/   /_ "
    echo "\_/   \____//_/   \____/\____/\____/\____/\____/\____/ "
    echo                                                  
    echo
    echo "Press Ctrl + C To Exit This Loop"
    command anonsurf change
    sleep 8
    done
}
psycostoolbox() {
    command clear
    echo
    echo "This Section Contains Other Projects Made By Me(psycolulz)"
    echo
    echo "1. PsycoScrape - Web Application Scanner"
    echo "2. AutoMap - NMAP Cheat-Sheet"
    echo "3. SQLMentor - SQLmap Cheat-Sheet"
    echo "4. Back"
    echo
    read -p $'Enter Option Here:' toolbox
    if [[ $toolbox == "1" ]]
    then
    psycoscrape 
    elif [[ $toolbox == "2" ]]
    then
    automap 
    elif [[ $toolbox == "3" ]]
    then 
    sqlmentor 
    elif [[ $toolbox == "4" ]]
    then
    main 
    else
    command clear
    psycostoolbox
    fi
}
psycoscrape() {
    command clear
    echo
    echo "1. Enter A Host To Scan (without https://)"
    echo "2. Back"
    read -p $'Enter Option Here' psycoscrapeoption
    if [[ $psycoscrapeoption == "1" ]]
    then
    psycoenterhost
    elif [[ $psycoscrapeoption == "2" ]]
    then
    psycostoolbox
    else
    command clear
    psycoscrape
    fi
}
psycoenterhost() {
    command clear
echo
echo
echo "Enter Hostname Below Without https://" 
read psycodomain
psycoscansite
}
psycoscansite() {
command clear 
echo
echo "                       _ "          
echo "   /\  /\___  __ _  __| | ___ _ __ "
echo "  / /_/ / _ \/ _; |/ _; |/ _ \ ;__|"
echo " / __  /  __/ (_| | (_| |  __/ |"   
echo " \/ /_/ \___|\__._|\__._|\___|_|"   
echo                          
command HEAD $psycodomain  
echo
echo
echo "xxxxxxx      xxxxxxx  ssssssssss       ssssssssss"   
echo " x:::::x    x:::::x ss::::::::::s    ss::::::::::s"  
echo "  x:::::x  x:::::xss:::::::::::::s ss:::::::::::::s" 
echo "   x:::::xx:::::x s::::::ssss:::::ss::::::ssss:::::s"
echo "    x::::::::::x   s:::::s  ssssss  s:::::s  ssssss" 
echo "     x::::::::x      s::::::s         s::::::s"      
echo "     x::::::::x         s::::::s         s::::::s"   
echo "    x::::::::::x  ssssss   s:::::s ssssss   s:::::s" 
echo "   x:::::xx:::::x s:::::ssss::::::ss:::::ssss::::::s"
echo "  x:::::x  x:::::xs::::::::::::::s s::::::::::::::s" 
echo " x:::::x    x:::::xs:::::::::::ss   s:::::::::::ss"  
echo "xxxxxxx      xxxxxxxsssssssssss      sssssssssss"    
echo
command nmap --script exploit -Pn $psycodomain
echo
echo "   __       _           _        _         _    "
echo "  /__\ ___ | |__   ___ | |_ ___ | |___  _ | |_  "
echo " / \/// _ \| ;_ \ / _ \| __/ __|| __\ \/ /  __| "
echo "/ _  \ (_) | |_) | (_) | |_\__ \| |_ >  <|  |_  "
echo "\/ \_/\___/|_;__/ \___/ \__|___(_)__/_/\_\ \__| "
echo                                                 
echo
command wget $psycodomain/robots.txt   
echo
echo
echo "   ___                      _                       _       "
echo "  / __\ __ ___  ___ ___  __| | ___  _ __ ___   __ _(_)_ __ " 
echo " / / | ;__/ _ \/ __/ __|/ _; |/ _ \| ;_ ; _ \ / _; | | ;_ \ "
echo "/ /__| | | (_) \__ \__ \ (_; | (_) | | | | | | (_| | | | | |"
echo "\____/_|  \___/|___/___/\__._|\___/|_| |_| |_|\__._|_|_| |_|"
echo
command wget $psycodomain/crossdomain.xml  
echo
echo
echo "        ___    __  __    "
echo "       /   \/\ \ \/ _\  " 
echo "      / /\ /  \/ /\ \  "  
echo "     / /_// /\  / _\ \ "  
echo "    /___,/\_\ \/  \__/"  
echo
echo 
command dig $psycodomain all
echo
echo
echo "Press Ctrl + C"
sleep 100
} 
automap() {
    command clear
    echo "1. Wordpress Username Enumeration"
    echo "2. NMAP XSS Vulnerability Check"
    echo "3. NMAP DNS Bruteforce"
    echo "4. NMAP Get Header Information"
    echo "5. NMAP Port Scanning"
    echo "6. Back"
    read -p $'Choose an option:' choice
    if [[ $choice == "1" ]] 
    then
    wordpressenum
    elif [[ $choice == "2" ]] 
    then
    xssvuln
    elif [[ $choice == "3" ]] 
    then
    dnsbrute
    elif [[ $choice == "4" ]] 
    then
    headerinfo
    elif [[ $choice == "5" ]] 
    then 
    portscan 
    elif [[ $choice == "6" ]] 
    then
    psycostoolbox
    else
    clear
    automap
fi
}
wordpressenum() {
command clear 
echo
echo
echo "Enter Hostname Without https://" 
echo
read wordpressdomain
command nmap -sV --script http-wordpress-users --script-args limit=50 $wordpressdomain
echo
echo "Sleep Is Set To 100, Exit Tool To Restart"
sleep 100
command clear
}
xssvuln() {
command clear
echo
echo
echo "Enter Hostname Without https://"
echo
read xssdomain
command nmap --script exploit -Pn $xssdomain
echo
echo 
echo "Sleep Is Set To 100, Exit Tool To Restart"
sleep 100
command clear
}
dnsbrute() {
command clear
echo
echo
echo "Enter Hostname Without https://"
echo
read dnsdomain 
command nmap -sP --script discovery $dnsdomain
echo
echo "Sleep Is Set To 100, Exit Tool To Restart"
sleep 100
command clear
}
headerinfo() {
command clear
echo
echo
echo "Enter Hostname Without https://"
echo
read headerdomain
command nmap -p80 --script http-useragent-tester.nse $headerdomain
echo 
echo
echo "Sleep Is Set To 100, Exit Tool To Restart"
sleep 100
command clear
}
portscan() {
command clear 
echo
echo
echo "Enter Hostname Without https://"
echo
read portdomain
command nmap $portdomain
echo
echo 
echo "Sleep Is Set To 100, Exit Tool To Restart"
sleep 100
command clear
}
sqlmentor() {
    command clear
    echo
    echo
    echo "1. SQL Crawling | 2. SQL Crawling + Forms | 3. SQL GET Req. | 4. SQL POST Req."
    echo "5. SQL Auth Site | 6. Collect DB & User | 7. SQL & Tables | 8. SQL User Columns"
    echo "9. SQL mssql DB | 10. SQL mysql DB | 11. SQL oracle DB | 12. SQL postgres DB"
    read -p $'Choose An Option:' choice
    if [[ $choice == "1" ]] 
    then
    crawling
    elif [[ $choice == "2" ]] 
    then
    crawlingforms
    elif [[ $choice == "3" ]] 
    then
    getreq
    elif [[ $choice == "4" ]] 
    then
    postreq
    elif [[ $choice == "5" ]] 
    then
    authsite
    elif [[ $choice == "6" ]] 
    then
    dbuser
    elif [[ $choice == "7" ]] 
    then
    sqltables
    elif [[ $choice == "8" ]] 
    then
    usercolumns
    elif [[ $choice == "9" ]] 
    then
    mssqldb
    elif [[ $choice == "10" ]] 
    then
    mysqldb
    elif [[ $choice == "11" ]] 
    then
    oracledb
    elif [[ $choice == "12" ]] 
    then
    postgresdb
    else
    command clear
    sqlmentor
    fi
}
crawling() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --crawl=2 --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
crawlingforms() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --forms --crawl=2 --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
getreq() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
postreq() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
authsite() {
echo
read -p $'Enter Full URL Below:' domain
command  sqlmap -u $domain --data="id=1&str=val" -p "id" --cookie="cookie1=val1;cookie2=val2" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
dbuser() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" -b --current-db --current-user --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
sqltables() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" --tables -D "testdb" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
usercolumns() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" --columns -T "users" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
mssqldb() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" -b --dbms="mssql" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
mysqldb() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" -b --dbms="mysql" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
oracledb() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" -b --dbms="oracle" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
postgresdb() {
echo
read -p $'Enter Full URL Below:' domain
command sqlmap -u $domain --data="id=1&str=val" -p "id" -b --dbms="postgres" --random-agent --tamper='space2comment'
echo
echo "Sleep Is Set To 100, Exit To Restart"
sleep 100
}
learningsources() {
    command clear
    echo
    echo "1. Learn About Different Web Vulnerabilities"
    echo "2. Learn About OSINT (Open-Source Intelligence)"
    echo "3. Learn About Malware And Prevention"
    echo "4. Learn About Tor"
    echo "5. Learn About Social Engineering"
    echo "6. Learn About Basics Of OpSec"
    echo "7. Learn About Proper Anonymity"
    echo "8. Back"
    echo
    read -p $'Enter Learning Option Here:' learningoption
    if [[ $learningoption == "1" ]] 
    then
    webvulnlearn
    elif [[ $learningoption == "2" ]] 
    then
    osintlearn
    elif [[ $learningoption == "3" ]] 
    then
    malwarelearn
    elif [[ $learningoption == "4" ]] 
    then
    torlearn
    elif [[ $learningoption == "5" ]] 
    then
    socialenglearn
    elif [[ $learningoption == "6" ]] 
    then
    opseclearn
    elif [[ $learningoption == "7" ]] 
    then
    anonymitylearn
    elif [[ $learningoption == "8" ]] 
    then
    main
    else
    command clear
    learningsources
    fi
}
webvulnlearn() {
    command clear
    echo
    echo "1. Cross-Site Scripting (XSS)  "
    echo "2. SQL Injection               "
    echo "3. Click-Jacking               "
    echo "4. DDoS Attacks                "
    echo "5. Remote File Inclusion (RFI) "
    echo "6. Session Fixation            "
    echo "7. Insecure Deserialization    "
    echo "8. Broken Authentication       "
    echo "9. XML External Entities       "
    echo "10. Back                       "
    echo
    read -p $'Enter Web Learning Option Here:' webvulnchoice
    if [[ $webvulnchoice == "1" ]]
    then
    crosssitescript
    elif [[ $webvulnchoice == "2" ]]
    then
    sqlinj
    elif [[ $webvulnchoice == "3" ]]
    then
    clickjacking
    elif [[ $webvulnchoice == "4" ]]
    then
    ddosattck
    elif [[ $webvulnchoice == "5" ]]
    then
    rfiinfo
    elif [[ $webvulnchoice == "6" ]]
    then
    sessionfix
    elif [[ $webvulnchoice == "7" ]] 
    then
    insecuredeserial
    elif [[ $webvulnchoice == "8" ]]
    then
    brokenauth
    elif [[ $webvulnchoice == "9" ]]
    then
    xmlexternal
    elif [[ $webvulnchoice == "10" ]]
    then
    learningsources
    else
    command clear
    webvulnlearn
    fi
}
crosssitescript() {
    command clear
    command firefox https://www.exploit-db.com/docs/english/18895-complete-cross-site-scripting-walkthrough.pdf &
    main
}
sqlinj() {
    command clear
    command firefox https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_1-SQL-Injections.pdf &
    main
}
clickjacking() {
    command clear
    command firefox https://frederik-braun.com/xfo-clickjacking.pdf &
    main
}
ddosattack() {
    command clear
    command firefox https://www.menog.org/presentations/menog-16/380-30_min_-__An_Introduction_to_Distributed_Denial_of_Service_Attacks_-_Menog_v3.pdf &
    main
}
rfiinfo() {
    command clear
    command firefox https://www.imperva.com/docs/HII_Remote_and_Local_File_Inclusion_Vulnerabilities.pdf &
    main
}
sessionfix() {
    command clear
    command firefox https://owasp.org/www-pdf-archive/OWASP_AppSec_Research_2010_Session_Fixation_by_Schrank_Braun_Johns_and_Poehls.pdf &
    main
}
insecuredeserial() {
    command clear
    command firefox https://www.safe.security/assets/img/research-paper/pdf/Introduction%20to%20Insecure%20Deserialization.pdf &
    main
}
brokenauth() {
    command clear
    command firefox https://owasp.org/www-chapter-ghana/assets/slides/OWASP_broken_authentication.pdf &
    main
}
xmlexternal() {
    command clear
    command firefox https://owasp.org/www-pdf-archive/XML_Exteral_Entity_Attack.pdf &
    main
}
osintlearn() {
    command clear
    echo
    echo "1. OSINT - Common Tools And How To Use Them Safely                               "
    echo "2. Open source intelligence: Introduction, legal, and ethical considerations     "
    echo "3. Back                                                                          "
    echo
    read -p $'Enter Osint Option Here:' osintoption
    if [[ $osintoption == "1" ]]
    then
    osintoptionone
    elif [[ $osintoption == "2" ]]
    then
    osintoptiontwo
    elif [[ $osintoption == "3" ]]
    then
    learningsources
    else
    command clear
    osintlearn
    fi
}
osintoptionone() {
    command clear
    command firefox https://www.bu.edu/tech/files/2020/08/BU-Security-Camp-2020-OSINT.pdf &
    main
}
osintoptiontwo() {
    command clear
    command firefox https://www.researchgate.net/publication/356506616_Open_source_intelligence_Introduction_legal_and_ethical_considerations &
    main
}
malwarelearn() {
    command clear
    echo
    echo "1. Different Types of Malware   "
    echo "2. How To Avoid Malware         "
    echo "3. How To Remove Malware        "
    echo "4. Back                         "
    read -p $'Enter Malware Option Here:' malwareoption
    if [[ $malwareoption == "1" ]]
    then
    differenttypes
    elif [[ $malwareoption == "2" ]]
    then
    howtoavoid
    elif [[ $malwareoption == "3" ]]
    then
    howtoremove
    elif [[ $malwareoption == "4" ]]
    then
    learningsources
    else
    command clear
    malwarelearn
    fi
}
differenttypes() {
    command clear
    command firefox https://techsupportwhale.com/wp-content/uploads/2020/05/Types-of-Malware.pdf &
    main
}
howtoavoid() {
    command clear
    command firefox https://docs.microsoft.com/en-us/microsoft-365/security/intelligence/prevent-malware-infection?view=o365-worldwide &
    main
}
howtoremove() {
    command clear
    command firefox https://consumer.ftc.gov/articles/how-recognize-remove-avoid-malware#remove &
    main
}
torlearn() {
    command clear
    echo
    echo "Welcome To The Tor Section, Here You Will Learn About The Wonders Of Tor And The Lack Thereof."
    echo
    echo
    echo "Tor is not as secure as people think it is, honestly im surprised anyone still thinks its secure lmfao."
    echo "Yes tor can mask your IP blah blah blah. The feds have access to most tor nodes if not all lmfao. You can use" 
    echo "tor to spoof your IP address if you are doing something that isnt illegal, thats perfectly fine. As a matter" 
    echo "of fact, let me start talking about the wonders of Tor!!!"
    echo
    echo "Tor offers uncensored and unlimited access to the wonders and monstrousities of the interwebs. Human trafficking,"
    echo "drug markets, illegal gun sales, forums, all can be accessed through tor. You probably shouldnt though, just saying."
    echo "As a source of looking for information, Tor can be very useful. You can access a lot of documents and resources that"
    echo "you might not be able to acces via the clearweb. That being said, there are many things you should look out for. As" 
    echo "previously stated, the feds have access to pretty much every part of tor. They can easily decrypt your traffic and" 
    echo "locate you, so here are things you should look out for. "
    echo
    echo " thehiddenwiki is not somewhere that you want to go for links to the dark web. Most of those sites, well..." 
    echo "pretty much all of those sites are shutdown/honeypots, just dont even bother with it lol. A lot of gun sites"
    echo "and drug markets are honeypots set up by the piggies (feds) to catch people trying to make illegal purchases."
    echo "Ive seen some sites on tor that advertise the sales of firearms, drugs, etc.. and use payments like paypal and "
    echo "card... instead of cryptocurrency. That should be an immediate red flag. Both of those payment options are traceable,"
    echo "without much effort to be honest, especially by the authorities. If you do decide to make a purchase on tor that "
    echo "for whatever reason is illegal, you should have an anonymous crypto wallet set up and make payments through that."
    echo "Do not use a crypto wallet that is linked to your identity, for example, coinbase. That should be general knowledge" 
    echo "but I know plenty of people lack basic knowledge on Anonymity and Tor." 
    echo
    echo "When it comes to forums, be very fucking careful. Do not click any links that anyone sends, no files, nothing." 
    echo "Do not trust anybody that you meet on tor. I do not care what they tell you, or if it is true or not. Assume they"
    echo "are lying. Do not give out any info about you. No social media platforms, no nicknames, do not use an alias that "
    echo "you already use, and make sure your alias in forums isnt something that relates to it. You do not want anyone" 
    echo "to know who you are, what you do, nothing. You can go to a friend group and do that, but not on tor." 
    echo
    echo "1. Back"
    read -p $'Enter Option Here:' torexit
    if [[ $torexit == "1" ]]
    then 
    learningsources
    else
    command clear
    torlearn
    fi
}
socialenglearn() {
    command clear
    echo
    echo "1. Introduction To Social Engineering"
    echo "2. Social Engineering: The Art Of Human Hacking"
    echo "3. Back"
    read -p $'Enter Social Engineering Option Here:' socialchoice
    if [[ $socialchoice == "1" ]]
    then
    seintro
    elif [[ $socialchoice == "2" ]]
    then 
    arthumanhacking
    elif [[ $socialchoice == "3" ]]
    then
    learningsources
    else
    command clear
    socialenglearn
    fi
}
seintro() {
    command clear
    command firefox https://info.publicintelligence.net/UK-CERT-SocialEngineering.pdf &
    main
}
arthumanhacking() {
    command clear
    command firefox https://owasp.org/www-pdf-archive/Presentation_Social_Engineering.pdf &
    main
}
opseclearn() {
    command clear
    echo
    echo "1. Introduction To OpSec"
    echo "2. OpSec - An In Depth Explanation" 
    echo "3. Back"
    read -p $'Enter Opsec Choice Here:' opsecchoice 
    if [[ $opsecchoice == "1" ]]
    then
    opsecintro
    elif [[ $opsecchoice == "2" ]]
    then
    indepthopsec
    elif [[ $opsecchoice == "3" ]]
    then
    learningsources
    else
    command clear
    opseclearn
    fi
}
opsecintro() {
    command clear
    command firefox https://edelweissemployees.weebly.com/uploads/2/8/3/8/28382059/ho-day_2_opsec_info_page.pdf?c=mkt_w_chnl:aff_geo:all_prtnr:sas_subprtnr:1538097_camp:brand_adtype:txtlnk_ag:weebly_lptype:hp_var:358504&sscid=91k6_26smv &
    main
}
indepthopsec() {
    command clear
    command firefox https://ncms-antelopevalley.org/Helpful-Links/OPSEC.pdf &
    main
}
anonymitylearn() {
    command clear
    echo
    echo "How Does One Become Anonymous?"
    echo
    echo "In This Section, I Will Personally Teach You How To Be Anonymous Online."
    echo
    echo "When evaluating and exploiting your targets, it is imperative that you do so effeciently, and most" 
    echo "importantly, safely. So how does one do so safely? The most important thing to remember is that you"
    echo "should never perform any type of Cyber Attack from your home. It doesnt matter if you think your" 
    echo "connection is secure enough or if you know what youre doing, it is never a good idea to perform"
    echo "attacks from your home. Go to an internet cafe or a McDonalds, somewhere that provides public wifi"
    echo "and has a lot of internet traffic daily. Next, using cheap and easily replaceable devices and" 
    echo "equipment is key. Using expensive and fancy equipment can screw you over in the end. At some point" 
    echo "in time you will have smash and ditch a few different devices to avoid being caught. Burner phones can"
    echo "come as cheap as ten bucks, and service on them is cheap. Stocking up on a few burner phones never hurts,"
    echo "I have been doing that for quite a while. Same goes for a computer, get one that is cheap and replaceable,"
    echo "so if it ever comes down to it, you can just smash, ditch, and replace. Now comes the question that most" 
    echo "people ask, what about a vpn or proxy? The truth is, a lot of vpns log your activity and IP address and" 
    echo "are more than happy to sell your data to companies and the government. Many VPN providers comply with" 
    echo "the authorities and will hand over your information to help an investigation against you when they are" 
    echo "subpoenaed. Look for VPNs that do not collect any of your information and are not compliant with federal"
    echo "entities. Tor, good ol tor. Tor does not make you invincible, unfortunately a lot of tor traffic is monitored"
    echo "by the federal government lol. Tor does allow uncensored internet access and some anonymity though. Now" 
    echo "comes some very important information. Dont tell anyone who you are or what you are doing when it comes" 
    echo "to hacking. No information about your interests, nothing about your life, nothing at all. Every piece" 
    echo "of information about you can become useful in the hands of the wrong person. You do not know who is really" 
    echo "on the other end of your screen, regardless of what they tell you. When posting photos or screenshots," 
    echo "make sure things like time, location indicators, basically anything that can indicate identity or location,"
    echo "are not in the photo or are completely covered up. Meta Data is also very important to keep in mind." 
    echo "Whenever you send a photo or video, they contain what is called exif data. That information can indicate" 
    echo "device information, location, and other information by viewing the exif data. There are ways you can" 
    echo "remove or change the exif data of an image or video. There are a few apps online and on the app store."
    echo "Another important thing to remember, it doesnt matter if it is online or in person, do not tell anyone" 
    echo "anything about what you are doing involving hacking. Everything you do leaves trails, the less trails"
    echo "you leave, the better your chances of not getting caught are. That includes loved ones and friends."
    echo "Trust no one. An alias is very important. You must choose a fake name or nickname to be identified as" 
    echo "online. Do not make it anything related to you or your interests, as again, they can be identifiers."
    echo
    echo "Secure communications are also imperative. Every social media platform gathers some form of information"
    echo "about you, for multiple purposes (i.e. Selling your data to companies and logging your information). Do" 
    echo "not discuss operations or illegal actions on social media or any unencrypted platform that keeps logs." 
    echo "Your best options are IRCs, keybase, chatcrypt, etc. I dont care what anyone says, dont use telegram."
    echo "Encrypted email services and throwaway phone numbers are important as well. Protonmail is ok for making"
    echo "accounts on social media platforms, but do not use protonmail to send any emails that are illegal."
    echo "There are better options like anonymail or guerilla mail for sending emails." 
    echo
    echo "Let me put it this way, if you think you are secure enough, then you still need to try to be even more secure."
    echo "Even the greats fucked up at some point and their anonymity failed. You have to be at the tip top of your" 
    echo "game to be truly secure. Do your research on all the services you use, check which information they have"
    echo "access to about you. We are in the age of information, privacy is not a luxury that many of us have. So" 
    echo "do whatever it takes to get a firm grasp on your privacy."
    echo
    echo "1. Back"
    read -p $'Enter Option Here:' anonymityexit 
    if [[ $anonymityexit == "1" ]]
    then
    learningsources
    else
    command clear
    anonymitylearn
    fi
}
privacy() {
    command clear
    echo
    echo "1. Removing Personal Public Records"
    echo "2. VPNs and Proxies"
    echo "3. Phone Numbers And emails"
    echo "4. Social Media Data" 
    echo "5. Back"
    echo
    read -p $'Enter Option Here:' privacyoption
    if [[ $privacyoption == "1" ]]
    then
    removingrec
    elif [[ $privacyoption == "2" ]]
    then
    vpnproxy
    elif [[ $privacyoption == "3" ]]
    then
    phoneemail
    elif [[ $privacyoption == "4" ]]
    then
    socialmedia
    elif [[ $privacyoption == "5" ]]
    then
    main
    else
    command clear
    privacy 
    fi
}
removingrec() {
    command clear
    echo
    echo "1. WhitePages Record Removal"
    echo "2. TruePeopleSsearch Record Removal"
    echo "3. FastPeopleSearch Record Removal"
    echo "4. FastBackgroundCheck Record Removal"
    echo "5. NumLookup Record Removal"
    echo "6. 192 Record Removal"
    echo "7. Intelius Record Removal"
    echo "8. Back"
    echo
    read -p $'Enter Option Here:' removalopt
    if [[ $removalopt == "1" ]]
    then
    whitepage 
    elif [[ $removalopt == "2" ]]
    then
    truepeople 
    elif [[ $removalopt == "3" ]]
    then
    fastpeople 
    elif [[ $removalopt == "4" ]]
    then
    fastbackground 
    elif [[ $removalopt == "5" ]]
    then
    numlookup 
    elif [[ $removalopt == "6" ]]
    then
    remove192
    elif [[ $removalopt == "7" ]]
    then
    intelius
    elif [[ $removalopt == "8" ]]
    then
    privacy
    else
    command clear
    removingrec
    fi
}
whitepage() {
    command clear
    echo
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $'Enter Option Here:' whitepageopt
    if [[ $whitepageopt == "1" ]]
    then
    command firefox https://www.whitepages.com/suppression-requests &
    elif [[ $whitepagesopt == "2" ]]
    then
    removingrec
    else
    command clear
    whitepage
    fi
}
truepeople() {
    command clear
    echo
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $'Enter Option Here:' trueoption
    if [[ $trueoption == "1" ]]
    then
    command firefox https://www.truepeoplesearch.com/removal &
    elif [[ $trueoption == "2" ]]
    then
    removingrec 
    else
    command clear
    truepeople 
    fi 
}
fastpeople() {
    command clear
    echo
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $'Enter Option Here:' fastoption
    if [[ $fastoption == "1" ]]
    then
    command firefox https://www.fastpeoplesearch.com/removal &
    elif [[ $fastoption == "2" ]]
    then
    removingrec
    else
    command clear
    fastpeople
    fi
}
fastbackground() {
    command clear
    echo
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $'Enter Option Here:' fastbackopt
    if [[ $fastbackopt == "1" ]]
    then
    command firefox https://www.fastbackgroundcheck.com/opt-out &
    elif [[ $fastbackopt == "2" ]]
    then
    removingrec
    else
    command clear
    fastbackground
    fi
}
numlookup(){
    command clear
    echo 
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $"Enter Option Here" numlookopt
    if [[ $numlookopt == "1" ]]
    then
    command firefox https://www.numlookup.com/opt_out &
    elif [[ $numlookopt == "2" ]]
    then
    removingrec
    else
    command clear
    numlookup
    fi
}
remove192(){
    command clear
    echo 
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $"Enter Option Here:" opt192
    if [[ $opt192 == "1" ]]
    then
    command firefox https://www.192.com/c01/new-request/ &
    elif [[ $opt192 == "2" ]]
    then
    removingrec
    else
    command clear
    192
    fi
}
intelius() {
    command clear
    echo 
    echo "1. Open Removal Page"
    echo "2. Back"
    echo
    read -p $'Enter Option Here:' inteliusopt
    if [[ $inteliusopt == "1" ]]
    then
    command firefox https://www.intelius.com/opt-out/submit/ &
    elif [[ $inteliusopt == "2" ]]
    then
    removingrec
    else
    command clear
    intelius
    fi
}
vpnproxy() {
    command clear
    echo
    echo "1. Privacy Focused VPNs"
    echo "2. Tor Proxies"
    echo "3. Back"
    echo
    read -p $'Enter Option Here:' vpnproxyoption
    if [[ $vpnproxyoption == "1" ]]
    then
    privvpn
    elif [[ $vpnproxyoption == "2" ]]
    then
    torproxies
    elif [[ $vpnproxyoption == "3" ]]
    then
    privacy
    else
    command clear
    vpnproxy
    fi
}
privvpn() {
    command clear
    echo
    echo "1. HotSpot-Shield (Free Or Paid)"
    echo "2. Express VPN (Paid)"
    echo "3. Proton VPN"
    echo "4. CyberGhost VPN"
    echo "5. Back"
    echo
    read -p $'Enter Option Here' vpnoption 
    if [[ $vpnoption == "1" ]]
    then
    command firefox https://hotspotshield.com/ &
    elif [[ $vpnoption == "2" ]]
    then
    command firefox https://expressvpn.com/ &
    elif [[ $vpnoption == "3" ]]
    then
    command firefox https://protonvpn.com/ &
    elif [[ $vpnoption == "4" ]]
    then
    command firefox https://cyberghostvpn.com/ &
    else
    command clear
    vpnproxy
    fi
}
torproxies() {
    command clear
    echo
    echo "1. AnonSurf Tor Proxy (Windows)"
    echo "2. Orxy Tor Proxy (Android)"
    echo "3. Back"
    echo 
    read -p $'Enter Option Here:' torproxyopt
    if [[ $torproxyopt == "1" ]]
    then
    command firefox https://github.com/ultrafunkamsterdam/AnonSurf &
    elif [[ $torproxyopt == "2" ]]
    then
    command firefox https://play.google.com/store/apps/details?id=com.inetric.orxy&hl=en_US&gl=US &
    elif [[ $torproxyopt == "3" ]]
    then
    vpnproxy
    else
    command clear
    torproxies
    fi
}
phoneemail() {
    command clear
    echo
    echo "1. List Of Phone Providers"
    echo "2. List Of Secure Email Services"
    echo "3. Back"
    echo
    read -p $'Enter Option Here:' phonemailopt
    if [[ $phonemailopt == "1" ]]
    then
    phoneprov
    elif [[ $phonemailopt == "2" ]]
    then
    emailserv
    elif [[ $phonemailopt == "3" ]]
    then
    privacy
    else
    command clear
    phoneemail
    fi
}
phoneprov() {
    command clear
    echo
    echo "TextNow"
    echo "2nd Line"
    echo "TextFree"
    echo "Google Voice"
    echo "Tracfone (Cheap Phones And Service Provider)"
    echo "PinePhone (Mobile Linux Distro)"
    echo "FreedomPhone (Private & Uncensored Phone)"
    echo
    echo "1. Back"
    echo
    read -p $'Enter Option Here:' phoneprovopt
    if [[ $phoneprovopt == "1" ]]
    then
    phoneemail
    else
    command clear
    phoneprov
    fi
}
emailserv() {
    command clear
    echo
    echo "ProtonMail (Encrypted Email Service)"
    echo "GuerillaMail (Temporary Email Service)"
    echo "AnonmMail (No Accounts, Encrypted Email Sender)"
    echo 
    echo "1. Back"
    echo
    read -p $'Enter Option Here:' emailservopt
    if [[ $emailservopt == "1" ]]
    then
    phoneemail
    else
    command clear
    emailserv
    fi 
}
socialmedia() {
    command clear
    echo
    echo "What Type Of Personal Data Does Social Media Collect?"
    echo
    echo "It is very important to understand exactly what types of information a platform"
    echo "is gathering about you. For example, Instagram:"
    echo
    echo "==========================================================="
    echo "Phone Information"
    echo "IP History"
    echo "Logs Used Emails"
    echo "Logs Used Phone Numbers"
    echo "Stores Phone Contacts If Synced"
    echo "Saves Messages/Comments/Searches"
    echo "==========================================================="
    echo
    echo "All of this information can be useful to hackers, which brings us to our next point."
    echo "Always use secure emails and strong passwords, as well as Two Factor Authentication (2fa)"
    echo "A strong password consists of a combination of letters, numbers, and symbols."
    echo "A long password with those requirements is more likely to withstand most Brute-Force"
    echo "attacks. Keep your information out of the hands of everyone else :)"
    echo
    echo "1. Back"
    echo
    read -p $'Enter Option Here:' socialmediaopt
    if [[ $socialmediaopt == "1" ]]
    then
    privacy
    else
    command clear
    socialmedia 
    fi
}
vulnscanning() {
    command clear
    echo
    echo "1. Reverse DNS Lookup"
    echo "2. DNS BRUTE-FORCE"
    echo "3. XSS Vulnerability Check"
    echo "4. HTTP-ENUMERATION"
    echo "5. HTTP Header Information"
    echo "6. Wordpress-Username Enumeration"
    echo "7. Regular NMAP Scan"
    echo "8. back"
    read -p $'Enter Scanning Option Here:' scanningoption
    if [[ $scanningoption == "1" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command dig $host all
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "2" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command nmap -sP --script discovery $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "3" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command nmap --script exploit -Pn $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "4" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command nmap --script http-enum -Pn $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "5" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command HEAD $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "6" ]]
    then 
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command nmap -sV --script http-wordpress-users --script-args limit=50 $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "7" ]]
    then
    command clear
    echo
    read -p $'Enter Domain Here:' host
    command nmap $host
    echo "Default Timeout Is 30 Seconds, Please Copy Your Results"
    sleep 30
    main
    elif [[ $scanningoption == "8" ]]
    then
    main
    else 
    command clear
    vulnscanning
    fi
}
osintframeworksection() {
    command clear
    echo
    echo "              Miniature OSINT Framework v. 1.0"
    echo "------------------------------------------------------------"
    echo
    echo "1. Public Records Section" 
    echo "2. Email + Phone Number Section" 
    echo "3. Image Section (Reverse Search + Exif Data Viewer)" 
    echo "4. Official OSINT FRAMEWORK"
    echo "5. Back"
    echo
    read -p $'Enter OSINT Option Here:' osintoption
    if  [[ $osintoption == "1" ]]
    then
    publicrecords
    elif [[ $osintoption == "2" ]]
    then
    emailnumbersection
    elif [[ $osintoption == "3" ]]
    then
    imagesection
    elif [[ $osintoption == "4" ]]
    then
    officialframework
    elif [[ $osintoption == "5" ]]
    then
    main
    else
    command clear
    osintframework
    fi
}
publicrecords() {
    command clear
    echo
    echo "1. TruePeopleSearch"
    echo "2. FastPeopleSearch"
    echo "3. FastBackgroundCheck"
    echo "4. WhitePages"
    echo "5. NumLookup"
    echo "6. Melissa"
    echo "7. MobileCanada"
    echo "8. 192"
    echo "9. TruthFinder (paid resource)"
    echo "10. Back" 
    echo
    read -p $'Enter Public Records Option Here:' publicrec
    if [[ $publicrec == "1" ]]
    then
    truepeople 
    elif [[ $publicrec == "2" ]]
    then
    fastpeople 
    elif [[ $publicrec == "3" ]]
    then
    fastbackcheck
    elif [[ $publicrec == "4" ]]
    then
    whitepagescheck
    elif [[ $publicrec == "5" ]]
    then
    numlookupch
    elif [[ $publicrec == "6" ]]
    then
    melissach
    elif [[ $publicrec == "7" ]]
    then
    mobilecanada 
    elif [[ $publicrec == "8" ]]
    then
    check192
    elif [[ $publicrec == "9" ]]
    then
    truthfind 
    elif [[ $publicrec == "10" ]]
    then 
    osintframeworksection
    else
    command clear
    publicrecords
    fi
}
truepeople() {
    command clear
    command firefox https://truepeoplesearch.com/ &
}
fastpeople() {
    command clear
    command firefox https://fastpeoplesearch.com/ &
}
fastbackcheck() {
    command clear
    command firefox https://www.fastbackgroundcheck.com/ & 
}
whitepagescheck() {
    command clear
    command firefox https://www.whitepages.com/ &
}
numlookupch() {
    command clear
    command firefox https://www.numlookup.com/ &
}
melissach() {
    command clear
    command firefox https://www.melissa.com/v2/lookups/ &
}
mobilecanda() {
    command clear
    command firefox http://mobile.canada411.ca/ &
}
check192() {
    command clear
    command firefox https://www.192.com/ &
}
truthfind() {
    command clear
    command firefox https://truthfinder.com/ &
}
emailnumbersection() {
    command clear
    echo
    echo "1. Epieos (email information tool)"
    echo "2. Yellow Directory National Lookup (Phone Number Lookup)"
    echo "3. Back "
    read -p $'Enter Email/Number Option Here:' emailnumber 
    if [[ $emailnumber == "1" ]]
    then
    epieostool
    elif [[ $emailnumber == "2" ]]
    then
    yellowdirectory
    elif [[ $emailnumber == "3" ]]
    then
    osintframework
    else
    command clear
    emailnumbersection
    fi
}
epieostool() {
    command clear
    command firefox https://epieos.com/ &
    main
}
yellowdirectory() {
    command clear
    command firefox https://www.searchyellowdirectory.com/reverse-phone/ &
}
imagesection() {
    command clear
    echo
    echo "1. Labnol (Google Reverse Image Search)"
    echo "2. Tineye (Reverse Image Search Paid)"
    echo "3. Exif Viewer"
    echo "4. Back"
    read -p $'Enter Image Option Here:' imageoption
    if [[ $imageoption == "1" ]]
    then
    labnolsite
    elif [[ $imageoption == "2" ]]
    then
    tineyesite
    elif [[ $imageoption == "3" ]]
    then
    exifsite
    elif [[ $imageoption == "4" ]]
    then 
    osintframework
    else
    command clear
    imagesection
    fi
}
labnolsite() {
    command clear
    command firefox https://labnol.org/reverse/ &
    main
}
tineyesite() {
    command clear
    command firefox https://tineye.com/ &
    main
}
exifsite() {
    command clear
    command firefox http://exif-viewer.com/ &
    main
}
osintframework(){
    command clear
    command firefox https://osintframework.com/ &
    main
}
searchsection(){
    command clear
    echo
    echo "1. Yahoo"
    echo "2. Google"
    echo "3. DuckDuckGo"
    echo "4. Shodan"
    echo "5. Swisscows"
    echo "6. Bing"
    echo "7. Thingful"
    echo "8. Google Scholar"
    echo "9. Wolfram Alpha"
    echo "10. Metacrawler"
    echo "11. Yandex"
    echo "12. Back"
    read -p $'Enter Search Option Here:' searchoption
    if [[ $searchoption == "1" ]]
    then
    yahoosection
    elif [[ $searchoption == "2" ]]
    then
    googlesection
    elif [[ $searchoption == "3" ]]
    then
    duckduckgosection
    elif [[ $searchoption == "4" ]]
    then
    shodansection
    elif [[ $searchoption == "5" ]]
    then
    swisscowssection
    elif [[ $searchoption == "6" ]]
    then
    bingsection
    elif [[ $searchoption == "7" ]]
    then
    thingfulsection
    elif [[ $searchoption == "8" ]]
    then
    googlescholarsection
    elif [[ $searchoption == "9" ]]
    then
    wolframsection
    elif [[ $searchoption == "10" ]]
    then
    metacrawlersection
    elif [[ $searchoption == "11" ]]
    then
    yandexsection
    elif [[ $searchoption == "12" ]]
    then
    main
    else
    command clear
    searchsection
    fi
}
yahoosection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://www.yahoo.com/search?q="$searchterm" &
    main
}
googlesection(){
    command clear
    read -p $'Enter Search Term Here:' searchterm    
    command firefox https://www.google.com/search?q="$searchterm" &
    main
}
duckduckgosection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://duckduckgo.com/?q="$searchterm" &
    main
}
shodansection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://www.shodan.io/search?query="$searchterm" &
    main
}
swisscowssection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://swisscows.com/web?culture=en&query="$searchterm"&region=en-US &
    main 
}
bingsection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm 
    command firefox https://www.bing.com/search?q="$searchterm"&form=QBLH&sp=-1&pq=a&sc=8-1&qs=n&sk=&cvid=964DCC37CA0543809FD5D3A64106835F &
    main
}
thingfulsection() {
    command clear
    echo 
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://www.thingful.net/?what="$searchterm"&lat=20.05593126519445&lng=-27.94921875&z=3 &
    main
}
googlescholarsection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://scholar.google.com/scholar?hl=en&as_sdt=0%2C22&q="$searchterm"&btnG= &
    main
}
wolframsection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://www.wolframalpha.com/input/?i="$searchterm" &
    main
}
metacrawlersection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://www.metacrawler.com/serp?q="$searchterm"&sc=ESnQ21Bx9v6Y10 &
    main
}
yandexsection() {
    command clear
    echo
    read -p $'Enter Search Term Here:' searchterm
    command firefox https://yandex.com/search/?text="$searchterm"&lr=110248 &
    main
}
updatesection() {
    command clear
    command git pull
}
welcome