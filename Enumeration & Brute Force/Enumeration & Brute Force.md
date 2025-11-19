
# **Task 2 - Authentication Enumeration**

Authentication enumeration is like peeling back the layers of an onion - removing each layer of a system's security to reveal the real operations underneath. It's about piecing together a puzzle by understanding what clues reveal about the security of a system.

**Identifying Valid Usernames**

Knowing a valid username lets an attacker focus just on the password. Error messages that specify "this account doesn't exist" or "incorrect password" can hint at valid usernames, making an attacker's job easier.

**Password Policies**

Password creation guidelines provide valuable insights into password complexity. By understanding these policies, an attacker can tailor their strategy accordingly.
For example, this PHP code uses regex to require symbols, numbers, and uppercase letters:

<?php
$password = $_POST['pass'];
$pattern = '/^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/';

if (preg_match($pattern, $password)) {
    echo "Password is valid.";
} else {
    echo "Password is invalid. It must contain at least one uppercase letter, one number, and one symbol.";
}
?>

The error message reveals the requirements, allowing attackers to generate targeted password dictionaries.
Common Enumeration Targets

**Registration Pages**

Registration pages immediately indicate whether an email or username is available. If a registration attempt shows that a username is already taken, the application confirms its existence. Attackers exploit this by testing potential usernames to compile lists of active users.

**Password Reset Features**

Variations in password reset responses can unintentionally reveal whether a username exists. Attackers analyze these responses to refine their lists of valid usernames, improving the effectiveness of subsequent attacks.

**Verbose Errors**

Error messages that differentiate between "username not found" and "incorrect password" provide attackers with definitive clues about valid usernames for more targeted attacks.

**Data Breach Information**

Data from previous breaches allows attackers to test whether compromised usernames and passwords are reused across platforms. This demonstrates how a single data breach can ripple through multiple platforms.

**Answer the questions below**

<details><summary>What type of error messages can unintentionally provide attackers with confirmation of valid usernames?</summary>
Verbose errors</details>

# **Task 3 - Enumerating Users via Verbose Errors**

Verbose errors are detailed error messages that help developers debug applications but can unintentionally expose sensitive system information to attackers. Like overheard conversations, these errors reveal secrets meant to be kept hidden.

**Understanding Verbose Errors**

- Internal Paths: File paths and directory structures that might contain configuration files or secret keys.
- Database Details: Table names, column details, and database schema information.
- User Information: Usernames, email addresses, or other personal data that aid further attacks.

**Inducing Verbose Errors**

- Invalid Login Attempts

Intentionally entering incorrect credentials triggers error messages that distinguish between valid and invalid usernames. Different error messages for non-existent versus incorrect passwords reveal which usernames are active.

- SQL Injection

Inserting malicious SQL commands into entry fields causes database errors that expose schema details. For example, placing a single quote (') in a login field might reveal the database structure.

- File Inclusion/Path Traversal

Manipulating file paths with sequences like ../../ attempts to access restricted files, triggering errors that disclose internal paths and directory structures.

- Form Manipulation

Altering form fields or parameters tricks the application into displaying errors that reveal backend logic or expected data formats.

- Application Fuzzing

Sending unexpected inputs to various application parts identifies weak points. Tools like Burp Suite Intruder automate this by bombarding the application with varied payloads to provoke informative errors.

**Enumeration in Authentication Forms**

Verbose errors in login forms can be exploited to enumerate valid users. When testing different email addresses, the application may respond with distinct messages like "Email does not exist" for invalid emails versus "Invalid password" for valid emails with incorrect passwords.

![Lab Screenshot](001.png)
![Lab Screenshot](002.png)

**Automation Example**

Below is a Python script that automates email enumeration by analyzing error message differences:
pythonimport requests

![Lab Sceenshot](003.png)

Usage:

python3 script.py usernames_gmail.com.txt

The script tests each email from a wordlist and categorizes them as VALID or INVALID based on the error message received, allowing attackers to build lists of legitimate accounts for targeted attacks.

**Answer the questions below**

<details><summary>What is the valid email address from the list?</summary>
canderson@gmail.com</details>

# **Task 4 Exploiting Vulnerable Password Reset Logic**

 **Password Reset Flow Vulnerabilities**

Password reset mechanisms provide user convenience but require careful security implementation. Poorly secured reset processes can be easily exploited, allowing attackers to gain unauthorized access to accounts.
Common Reset Methods

**Email-Based Reset**

The application sends a reset link or token to the user's registered email. The user clicks the link to set a new password. This method's security depends on email account security and token secrecy.

**Security Question-Based Reset**

Users answer pre-configured security questions to verify identity. This can be compromised if attackers obtain personally identifiable information (PII) through social engineering or data breaches.

**SMS-Based Reset**

A reset code is sent via SMS to the user's mobile phone. While assuming phone security, this method is vulnerable to SIM swapping attacks or SMS interception.

Common Vulnerabilities

- Predictable Tokens: Sequential or simple patterns allow attackers to guess or brute-force valid reset URLs.
- Token Expiration Issues: Long-lived tokens or tokens that don't expire after use provide extended attack windows.
- Insufficient Validation: Weak security questions or easily compromised email authentication enable exploitation.
- Information Disclosure: Error messages revealing whether emails/usernames exist aid enumeration efforts.
- Insecure Transport: Non-HTTPS transmission exposes tokens to network interception.

**Exploiting Predictable Tokens**

Tokens that are simple or predictable can be brute-forced. For example, this vulnerable code generates a weak reset token:

![Lab Screenshot](004.png)

This code generates a simple 3-digit numeric token (100-200), making it trivial to brute-force.
Practical Exploitation

Step 1: Request a password reset for the target account (e.g., admin@admin.com).

Step 2: Capture the reset URL with Burp Suite:
http://enum.thm/labs/predictable_tokens/reset_password.php?token=123

Step 3: Generate a wordlist using Crunch:
bashcrunch 3 3 -o otp.txt -t %%% -s 100 -e 200
This creates a list of all numbers from 100 to 200.

Step 4: Configure Burp Suite Intruder:

![Lab Screenshot](005.png)

Send the request to Intruder
Highlight the token parameter value
Click "Add §" to mark it as the payload position
Load the generated otp.txt file as the payload

Step 5: Start the attack and look for responses with significantly larger content length, indicating successful token validation.

![Lab Screenshot](006.png)

Step 6: Use the valid token to set a new password and gain account access.

![Lab Screenshot](007.png)

**Answer the questions below**

<details><summary>What is the flag?</summary>
THM{50_pr3d1ct4BL333!!}</details>


# **Task 5 - Exploiting HTTP Basic Authentication**

**Basic Authentication in 2k24?**

Basic authentication provides a simple method for securing device access using only username and password credentials. While straightforward to implement, it lacks the robust security features of modern authentication schemes like OAuth or token-based systems.
Why Basic Auth Still Exists
Network devices like routers use basic authentication for administrative interfaces because:

Minimal processing overhead on resource-limited devices
No need for session management or user tracking
Simple configuration changes don't require complex authentication
Easy to implement and manage

How HTTP Basic Authentication Works
Defined in RFC 7617, HTTP Basic Authentication transports credentials as a base64-encoded string in the 

Authorization header:
Authorization: Basic <credentials>
Where <credentials> is the base64 encoding of username:password.
Critical Security Issue: Base64 is encoding, not encryption. It can be easily decoded, making credentials vulnerable over non-HTTPS connections. The primary threat comes from weak credentials susceptible to brute-force attacks.

**Exploitation**

**Step 1:** 

Capture the Request

Navigate to the target and enter any credentials. Capture the authentication request with Burp Suite:

GET /labs/basic_auth/ HTTP/1.1

Host: enum.thm

Authorization: Basic YWRtaW46cGFzc3dvcmQ=

**Step 2:** 

Configure Burp Intruder

Send the captured request to Intruder

Decode the base64 string in the Authorization header

Highlight the decoded credentials string

Click "Add §" to mark it as the payload position

**Step 3:** 

Configure Payloads

Payload Type: Simple list

Wordlist: Use a common password list like 500-worst-passwords.txt from SecLists

Payload Processing Rules (add in order):

Add prefix: admin: (prepends username to each password, e.g., 123456 becomes admin:123456)
Encode: Base64 (encodes the complete username:password string)

Payload Encoding: Remove the = character from the encoding list, as base64 uses it for padding.

**Step 4:** 

Execute Attack

Click "Start Attack" and monitor responses. Look for HTTP Status Code 200, which indicates successful authentication.

**Step 5:** 

Access the Account

Once you find a successful request:

Decode the base64 string from the Authorization header

Use the decoded credentials to access the application


**Answer the questions below**

<details><summary>What is the flag?</summary>
THM{b4$$1C_AuTTHHH}</details>


# **Task 6 - OSINT**

Examining a web application's past can reveal as much as its present. Historical data and search engine indexing often expose forgotten files, directories, and sensitive information still accessible on live servers.

**Wayback Machine**

The Internet Archive's Wayback Machine (https://archive.org/web/) archives historical versions of websites. Older versions may contain files and directories no longer visible but still present on the server, potentially providing backdoor access.

**Using waybackurls**

The waybackurls tool dumps all archived URLs from the Wayback Machine for a target domain:

![Lab Screenshot](008.png)

This reveals all historical URLs, including forgotten endpoints, admin panels, configuration files, and backup directories that may still be accessible.


**Google Dorks**

Google Dorks are specialized search queries that uncover information not meant to be public. By crafting specific queries, attackers can find exposed administrative directories, logs, backups, and sensitive files.

**Common Google Dork Patterns**

**Find administrative panels:**

site:example.com inurl:admin

**Discover log files containing passwords:**

filetype:log "password" site:example.com

**Locate backup directories:**

intitle:"index of" "backup" site:example.com

**Find configuration files:**

site:example.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini

**Expose database dumps:**

site:example.com ext:sql | ext:dbf | ext:mdb

**Identify exposed documents:**

site:example.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv


# **Task 7 - Conclusion**

Throughout this material, we explored various aspects of enumeration and brute force attacks on web applications, providing knowledge and practical skills for conducting thorough security assessments.

**Effective Enumeration: **

Proper enumeration is crucial for identifying potential vulnerabilities. Using appropriate tools and techniques reveals valuable information that aids in planning security testing and understanding application weaknesses.

**Brute Force Efficiency:** 

Optimizing brute force attacks involves creating intelligent wordlists, managing attack parameters, and understanding detection mechanisms like rate limiting and account lockout policies.

**Ethical Responsibility:** 

Always conduct enumeration and security testing with explicit permission from the system owner. Unauthorized testing is illegal and can have severe legal and professional consequences.

The techniques covered serve legitimate security assessment purposes including:

- Penetration testing with proper authorization
- Security research in controlled environments
- Bug bounty programs with defined scope
- Educational lab environments

Understanding these attack vectors helps security professionals better defend systems by identifying and remediating vulnerabilities before malicious actors can exploit them.