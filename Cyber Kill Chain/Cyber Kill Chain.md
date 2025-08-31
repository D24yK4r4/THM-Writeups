![Cover](001.png)
The Cyber Kill Chain® is a cybersecurity framework created by Lockheed Martin in 2011, based on a military attack model. It breaks down cyberattacks into sequential phases that adversaries must complete to succeed.

Understanding the Kill Chain helps defenders identify attack techniques, detect intrusions, and close security gaps. It is especially useful against ransomware, breaches, and APTs.

For SOC Analysts, Security Researchers, Threat Hunters, and Incident Responders, the framework provides a structured way to recognize attacks and understand attacker objectives.


# **Reconnaissance**

The planning phase where adversaries gather information about the target system and victim.
This includes OSINT: collecting publicly available data (company size, emails, phone numbers, employee details) to identify the best target for attack.

[What is OSINT?](https://www.varonis.com/blog/what-is-osint/)

Email Harvesting
The process of collecting email addresses from public, paid, or free sources. Attackers use these for phishing, a social engineering attack to steal sensitive data (e.g., logins, credit card numbers).

Common Tools

[theHarvester](https://github.com/laramies/theHarvester) – collects emails, names, subdomains, IPs, and URLs

[Hunter.io](https://hunter.io/) – finds contact info tied to a domain

[OSINT FRAMEWORK](https://osintframework.com/) – directory of OSINT tools by category

Attackers also leverage social media (LinkedIn, Facebook, Twitter, Instagram) to gather personal and company info, which can strengthen phishing attempts.

<details><summary>What is the name of the Intel Gathering Tool that is a web-based interface to the common tools and resources for open-source intelligence? </summary>

OSINT Framework
</details>
<details><summary>What is the definition for the email gathering process during the stage of reconnaissance? </summary>

Email harvesting
</details>


# **Weaponization**

After reconnaissance, the attacker creates a weaponizer – combining malware and an exploit into a deliverable payload.

Malware – software designed to damage or gain unauthorized access

Exploit – code that abuses a vulnerability

Payload – the malicious code executed on the target

Attackers may:

Use automated tools to generate malware

Buy malware from the Dark Web
(APT groups) write custom malware to evade detection

In this case, “Megatron” buys a pre-written payload to save time for later attack phases.

<details><summary>This term is referred to as a group of commands that perform a specific task. You can think of them as subroutines or functions that contain the code that most users use to automate routine tasks. But malicious actors tend to use them for malicious purposes and include them in Microsoft Office documents. Can you provide the term for it?</summary>

Macro
</details>

# **Delivery**

The attacker chooses how to transmit the payload or malware. Common methods include:

Phishing / Spearphishing emails – crafted using info from reconnaissance, targeting individuals or groups. Example: fake invoice email with payload.

USB Drop attacks – infected drives left in public or mailed with fake branding to trick employees.
You can read about these similar attacks at [CSO Online "Cybercriminal group mails malicious USB dongles to targeted companies."](https://www.csoonline.com/article/3534693/cybercriminal-group-mails-malicious-usb-dongles-to-targeted-companies.html)

Watering hole attacks – compromise a website frequently visited by the target group, redirecting them to a malicious site or causing a drive-by download (e.g., fake browser extension).

<details><summary>## What is the name of the attack when it is performed against a specific group of people, and the attacker seeks to infect the website that the mentioned group of people is constantly visiting.</summary>

Watering hole attack
</details>

# **Exploitation**

The attacker leverages vulnerabilities to gain system access:

Phishing emails – e.g., malicious link to fake login page or macro attachment executing ransomware.

Privilege escalation & lateral movement – moving deeper into the network to access sensitive data (CrowdStrike).

Zero-day exploits – unknown vulnerabilities exploited before detection ([FireEye](https://www.fireeye.com/current-threats/what-is-a-zero-day-exploit.html)).

Exploits can target software, hardware, servers, or even humans.

<details><summary> Can you provide the name for a cyberattack targeting a software vulnerability that is unknown to the antivirus or software vendors?</summary>

Zero-day
</details>


# **Installation**

After gaining access, the attacker installs a persistent backdoor to maintain access if detected, patched, or disconnected.

Techniques include:

Web shells – malicious scripts (.php, .asp, .jsp) on web servers, often hard to detect.

Backdoors – e.g., [Meterpreter](https://www.offensive-security.com/metasploit-unleashed/meterpreter-backdoor/) payload to interact remotely with the victim machine.

Windows services ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)) – create/modify services to run malicious code, sometimes masquerading as legitimate software.

Registry Run Keys / Startup Folder – payload runs on user login.

[Timestomping](https://attack.mitre.org/techniques/T1070/006/) – modifies file timestamps to evade forensic detection.

<details><summary>Can you provide the technique used to modify file time attributes to hide new or changes to existing files?</summary>

Timestomping
</details>

<details><summary>Can you name the malicious script planted by an attacker on the webserver to maintain access to the compromised system and enables the webserver to be accessed remotely?</summary>

Web shell
</details>


# **Command & Control**

After persistence, the attacker establishes a C2 channel to remotely control the victim machine.

C2 / C&C / Beaconing – infected host continuously communicates with attacker-controlled server.

Traditional channel: IRC (now largely obsolete due to detection).

Common modern channels:

HTTP / HTTPS (ports 80 / 443) – blends with normal traffic to evade firewalls.

DNS / DNS Tunneling – attacker-controlled DNS server receives constant requests.

C2 infrastructure can be owned by the attacker or another compromised host.


<details><summary>What is the C2 communication where the victim makes regular DNS requests to a DNS server and domain which belong to an attacker. </summary>

DNS Tunneling
</details>


# **Actions on Objectives (Exfiltration)**

With full access, the attacker completes their goals:

Credential harvesting – collect user login info

Privilege escalation – gain higher access (e.g., domain admin)

Internal reconnaissance – find vulnerabilities in internal systems

Lateral movement – move through the network

Data exfiltration – steal sensitive information

Backup/shadow copy deletion – remove recovery points

Data corruption/overwrite – sabotage or modify files

<details><summary>Can you provide a technology included in Microsoft Windows that can create backup copies or snapshots of files or volumes on the computer, even when they are in use? </summary>

Shadow Copy
</details>


# **Practice Analysis**

How did the data breach happen? Deploy the static site attached to this task and apply your skills to build the Cyber Kill Chain of this scenario. Here are some tips to help you complete the practical:

1. Add each item on the list in the correct Kill Chain entry-form on the Static Site Lab:

* exploit public-facing application
* data from local system
* powershell
* dynamic linker hijacking
* spearphishing attachment
* fallback channels

2. Use the ‘Check answers’ button to verify whether the answers are correct (where wrong answers will be underlined in red).

<details><summary>What is the flag after you complete the static site?</summary>

![Lab Screenshot](003.png)
THM{7HR347_1N73L_12_4w35om3}
</details>


# **Conclusion**

Limitations of the Cyber Kill Chain
The traditional Cyber Kill Chain (Lockheed Martin, 2011) helps improve network defense but is not perfect and shouldn’t be the only tool.

Focuses mainly on malware delivery and perimeter security, so it misses insider threats ([CISA
](https://www.cisa.gov/defining-insider-threats)).

Security gaps exist due to lack of updates and evolving adversary tactics (e.g., changing hashes, IPs).

Modern defenses include AI and advanced algorithms to detect subtle threats.

Recommendation: Use the Kill Chain alongside [MITRE ATT&CK](https://attack.mitre.org/)
 and [Unified Kill Chain](https://unifiedkillchain.com/)
 for a more comprehensive defense strategy.