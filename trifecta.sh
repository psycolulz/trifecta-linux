#!/bin/bash
tput bold
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
    echo "3  - Pinger ==================="
    echo "4  - Learning Resources ======="
    echo "5  - Pandoras Box(Dont Open) =="
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
    pingersection
    elif [[ $choice == "4" ]] 
    then
    learningsources
    elif [[ $choice == "5" ]] 
    then
    pandorasbox
    elif [[ $choice == "6" ]] 
    then
    vulnscanning
    elif [[ $choice == "7" ]] 
    then
    osintframework
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
pingersection() {
    command clear
    echo 
    echo "1. Ping A Host"
    echo "2. Back"
    echo
    read -p $'Enter Pinger Option Here:' pingeroption
    if [[ $pingeroption == "1" ]] then
    pingentry
    elif [[ $pingeroption == "2" ]] then
    main 
    else
    command clear
    pingersection
    fi
}
pingentry() {
    command clear
    echo 
    echo
    read -p $'Enter IP Or Hostname To Ping:' hostname 
    command ping $hostname
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
pandorasbox() {
    command clear
    command pandora bomb
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
osintframework() {
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
    echo "3. TruthFinder (paid resource)"
    echo "4. Back" 
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
    truthfind 
    elif [[ $publicrec == "4" ]]
    then 
    osintframework
    else
    command clear
    publicrecords
    fi
}
truepeople() {
    command clear
    command firefox https://truepeoplesearch.com/ &
    main
}
fastpeople() {
    command clear
    command firefox https://fastpeoplesearch.com/ &
    main
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
main 
