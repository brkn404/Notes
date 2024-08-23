Bug Bounty Hunting Checklist Addendum

This checklist builds upon the reference image and provides an enhanced guide for bug bounty hunting. It covers additional tools, techniques, and processes to help ensure thorough assessments.
1. Subdomain Enumeration

    Find Subdomains:
        Tools: Sublist3r, Amass, Assetfinder
        Command Example:

        bash

    sublist3r -d target.com
    amass enum -d target.com
    assetfinder --subs-only target.com

Check CNAME Records for Subdomain Takeover:

    Tools: Subjack, Subzy
    Command Example:

    bash

    subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c /path/to/fingerprints.json -v
    subzy --targets subdomains.txt

Use WaybackURLs for URL Discovery:

    Tools: Waybackurls, gau
    Command Example:

    bash

        echo "target.com" | waybackurls > urls.txt
        gau target.com > urls.txt

2. Port Scanning & Recon

    Use Masscan for Port Scanning:
        Command Example:

        bash

    masscan -p1-65535 target.com --rate=1000

Use Nmap for Service Enumeration:

    Command Example:

    bash

        nmap -sV -sC -p- -oN nmap_scan.txt target.com

3. Source Code and GitHub Recon

    Do GitHub Recon:
        Tools: Gitrob, TruffleHog, GitHub Dorking
        Command Example:

        bash

        gitrob target
        trufflehog --regex --entropy=False https://github.com/target/repo.git

4. Web Application Security Checks

    Check for WebApp Security Misconfigurations:
        Tools: Nikto, Nuclei
        Command Example:

        bash

    nikto -h target.com
    nuclei -t nuclei-templates -u target.com

Check for CORS Misconfiguration:

    Tools: CORStest, curl
    Command Example:

    bash

        python CORStest.py -u https://target.com
        curl -H "Origin: http://evil.com" -I https://target.com

5. Endpoint Discovery and Parameter Testing

    Use Arjun for Finding Hidden Parameters:
        Command Example:

        bash

    arjun -u https://target.com/api/v1/login

Check for CSRF Vulnerabilities:

    Tools: Burp Suite, OWASP ZAP
    Manual Testing: Ensure CSRF tokens are implemented and validated properly.

Check for XSS and SSTI:

    Tools: XSStrike, XSS Hunter
    Command Example:

    bash

    xsstrike -u https://target.com

Check for SSRF Parameters:

    Tools: Gopherus, SSRFmap
    Command Example:

    bash

        python gopherus.py
        python ssrfmap.py -u https://target.com -p parameter

6. Cryptography and Security Headers

    Check for Cryptography in Reset Password Token:
        Manual Testing: Look for weak encryption or predictable tokens.

    Check Security Headers:

        Tools: SecurityHeaders.com, curl

        Command Example:

        bash

        curl -I https://target.com

        Headers to Check:
            X-Frame-Options
            X-XSS-Protection
            Strict-Transport-Security
            Content-Security-Policy
            X-Content-Type-Options

7. Advanced Injection Techniques

    Check for SQLi, NoSQLi, and LDAP Injection:
        Tools: SQLmap, NoSQLmap
        Command Example:

        bash

    sqlmap -u https://target.com/page?id=1 --batch --dbs

Check for Command Injection:

    Tools: Commix
    Command Example:

    bash

        commix --url=https://target.com --data="param=value"

    Check for Buffer Overflow:
        Manual Testing: Review inputs that handle binary data or use fuzzing tools.

8. Directory and File Enumeration

    Directory Brute-Force:
        Tools: Dirbuster, Gobuster
        Command Example:

        bash

        gobuster dir -u https://target.com -w /path/to/wordlist.txt

    Check for File Upload Vulnerabilities:
        Manual Testing: Test file uploads for unrestricted file types, path traversal, etc.

9. Additional Checks

    Check for HTTP Request Smuggling:
        Tools: Burp Suite
        Manual Testing: Craft HTTP request with overlapping Content-Length and Transfer-Encoding headers.

    Check for Open Redirects:
        Manual Testing: Append URLs or modify existing parameters to see if redirection occurs.

    Check for Rate Limiting Bypass:
        Tools: Burp Suite Intruder
        Command Example:

        bash

        Intruder > Payload positions > Set to repeat a request and monitor responses

10. Final Vulnerability Checks

    Check for Common Web Vulnerabilities:
        Tools: OWASP ZAP, Burp Suite
        Manual Testing: Test for vulnerabilities like CSRF, XSS, SSRF, RCE, LFI, XXE.

Headers to Inspect

    X-Originating-IP: The originating IP of the client connecting to the server.
    X-Forwarded-For: The original client IP address when passing through proxies.
    X-Remote-IP: Another header variant for IP forwarding.
    X-Client-IP: The client's original IP address.
    X-Forwarded-Host: The original host requested by the client.

Additional Tools and Techniques

    Aquatone: Visual inspection tool for websites.
    Masscan: Fast port scanning tool.
    Knockpy: DNS enumeration tool.
    ParamSpider: OSINT tool for finding GET parameters in web archives.


Certainly! A bug bounty checklist is a crucial tool for ensuring that your vulnerability assessments are comprehensive and effective. Below, I've provided additional recommendations that you can incorporate into your bug bounty checklist:
11. Session Management and Authentication

    Check for Session Fixation:
        Tools: Burp Suite, OWASP ZAP
        Manual Testing: Attempt to set session cookies before login and see if they remain valid after authentication.

    Check for Weak Session Tokens:
        Manual Testing: Analyze session tokens for predictability or weak entropy.
        Tools: JWT Toolkit (for JWT tokens).

    Check for Insecure Direct Object References (IDOR):
        Manual Testing: Modify parameters that reference object IDs, such as user IDs, to access data belonging to other users.

    Check for Weak Password Policies:
        Manual Testing: Test password strength requirements and reset mechanisms for robustness.

12. API Security Testing

    Check for Exposed APIs:
        Tools: Postman, Insomnia
        Manual Testing: Review API documentation (if available) and endpoints for security flaws.

    Check for API Rate Limiting:
        Tools: Burp Suite Intruder
        Manual Testing: Send a high volume of requests to test if rate limiting is enforced.

    Check for API Authentication Bypass:
        Manual Testing: Attempt to bypass authentication by modifying API requests, using invalid tokens, or exploiting weak token validation.

    Check for Improper API Data Exposure:
        Manual Testing: Review API responses for sensitive data leakage, such as user data, tokens, or internal system information.

13. Cloud Security and Infrastructure

    Check for Exposed S3 Buckets:
        Tools: AWS CLI, s3scanner
        Command Example:

        bash

    aws s3 ls s3://bucket-name --no-sign-request

Check for Misconfigured Cloud Services:

    Tools: ScoutSuite, Prowler
    Manual Testing: Review cloud infrastructure for publicly exposed resources, weak permissions, and improper configurations.

Check for Publicly Accessible Secrets:

    Tools: TruffleHog, GitSecrets
    Command Example:

    bash

        trufflehog https://github.com/target/repo.git

14. Mobile Application Security

    Check for Insecure Data Storage:
        Tools: MobSF, Frida
        Manual Testing: Analyze mobile apps for improper data storage, such as sensitive data stored in plaintext or weakly encrypted formats.

    Check for Insecure Communication:
        Tools: Burp Suite, Wireshark
        Manual Testing: Intercept mobile app traffic to check if sensitive data is transmitted over insecure channels (e.g., HTTP).

    Check for Reverse Engineering Vulnerabilities:
        Tools: APKTool, Jadx
        Command Example:

        bash

        apktool d target.apk

    Check for Insecure API Integration:
        Manual Testing: Review API calls made by the mobile app for proper authentication and data handling.

15. Social Engineering and OSINT

    Check for Phishing Vulnerabilities:
        Manual Testing: Evaluate the target for vulnerabilities that could be exploited through phishing, such as insecure login pages or email spoofing.

    Conduct OSINT to Discover Exposed Information:
        Tools: theHarvester, Recon-ng
        Command Example:

        bash

    theHarvester -d target.com -b all

Check for Publicly Available Sensitive Information:

    Tools: Google Dorks, Shodan, Censys
    Command Example:

    bash

        site:target.com filetype:pdf confidential

16. Advanced Vulnerability Testing

    Check for Memory Corruption Issues:
        Tools: AFL, AddressSanitizer
        Manual Testing: Use fuzzing tools to discover memory corruption vulnerabilities in binaries or web applications.

    Check for Advanced Web Vulnerabilities:
        Tools: Arachni, W3af
        Command Example:

        bash

        arachni https://target.com

    Check for Multi-Step Logic Vulnerabilities:
        Manual Testing: Perform multi-step actions in web applications to identify logic flaws, such as bypassing steps in a checkout process.

17. Post-Exploitation and Reporting

    Check for Persistent XSS:
        Manual Testing: Ensure that XSS payloads persist across sessions or inputs, indicating a stored XSS vulnerability.

    Document and Report All Findings:
        Manual Reporting: Write detailed reports that include proof of concepts, impacted assets, steps to reproduce, and recommended mitigations.

    Check for Post-Exploitation Opportunities:
        Manual Testing: After identifying a vulnerability, consider whether it can lead to further exploitation, such as privilege escalation or lateral movement.

18. Continuous Learning and Updates

    Stay Updated with Latest Vulnerabilities:
        Tools: Exploit-DB, CVE Mitre
        Resources: Regularly check security blogs, subscribe to vulnerability mailing lists, and participate in bug bounty platforms.

    Practice on Vulnerable Labs:
        Platforms: Hack The Box, TryHackMe, VulnHub
        Manual Practice: Continuously practice on intentionally vulnerable applications to sharpen your skills.

19. Workflow Automation

    Automate Recon and Scanning:
        Tools: Reconbot, LazyRecon, Sn1per
        Command Example:

        bash

    sniper -t target.com

Set Up Continuous Scanning:

    Tools: Cron Jobs, CI/CD Pipelines
    Command Example:

    bash

        (cd /path/to/scans && ./run_scan.sh) > scan_output.log 2>&1

20. Collaboration and Knowledge Sharing

    Collaborate with Other Hunters:
        Platforms: Bugcrowd, HackerOne, Synack
        Manual Sharing: Engage with other bounty hunters, share knowledge, and learn from community findings.

    Contribute to Open Source Security Projects:
        Repositories: OWASP, SecLists
        Manual Contribution: Contribute to security tools and lists that help the community improve their testing processes.

Final Thoughts

Incorporating these additional recommendations into your bug bounty checklist will help you develop a more holistic approach to vulnerability hunting. By continuously refining your methodology, staying updated with the latest trends, and leveraging both manual and automated tools, you'll be well-equipped to discover and report vulnerabilities effectively.
ChatGPT can make mistakes. Check important info.