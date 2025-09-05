


Objective

After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.

Following the Pyramid of Pain's ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

Room Prerequisites

Completing the preceding rooms in the [Cyber Defence Frameworks module](https://tryhackme.com/module/cyber-defence-frameworks) will be beneficial before venturing into this challenge. Specifically, the following:

* [The Pyramid of Pain](https://tryhackme.com/room/pyramidofpainax)
* [MITRE](https://tryhackme.com/room/mitre)


Connection Details

Please click Start Machine to deploy the application, and navigate to https://LAB_WEB_URL.p.thmlabs.com once the URL has been populated.

Note: It may take a few minutes to deploy the machine entirely. If you receive a "Bad Gateway" response, wait a few minutes and refresh the page.

Question 1.

First step, open the mail
![Lab Screenshot](001.png)
send the sample1.exe file for Analys, check the infos
![Lab Screenshot](003.png)
Block the hash algorythm 
![Lab Screenshot](004.png)

<details><summary>What is the first flag you receive after successfully detecting sample1.exe?</summary>

![Lab Screenshot](002.png)
THM{f3cbf08151a11a6a331db9c6cf5f4fe4}</details>

Question 2.

Send the sample2.exe for Analys, check the infos
![Lab Screenshot](005.png)
![Lab Screenshot](006.png)
Block the IP address as it below
![Lab Screenshot](007.png)

<details><summary>What is the second flag you receive after successfully detecting sample2.exe?</summary>

![Lab Screenshot](008.png)
THM{2ff48a3421a938b388418be273f4806d}</details>

Question 3.

Send the sample3.exe for Analys
![Lab Screenshot](009.png)
![Lab Screenshot](010.png)

Create DNS Rule (block/deny)
![Lab Screenshot](011.png)

<details><summary>What is the third flag you receive after successfully detecting sample3.exe?</summary>
![Lab Screenshot](012.png)
THM{4eca9e2f61a19ecd5df34c788e7dce16}</details>

Question 4.

Submit sample4.exe for Analys
![Lab Screenshot](013.png)
![Lab Screenshot](014.png)
![Lab Screenshot](015.png)

Create Sigma Rule
![Lab Screenshot](016.png)
![Lab Screenshot](017.png)
![Lab Screenshot](018.png)
![Lab Screenshot](019.png)

<details><summary>What is the fourth flag you receive after successfully detecting sample4.exe?</summary>

![Lab Screenshot](020.ng.png)
THM{c956f455fc076aea829799c0876ee399}</details>

Question 5.

First check the outgoing_connections.log from the message
![Lab Screenshot](024.png)
Then send the sample5.exe for Analys
![Lab Screenshot](021.png)
![Lab Screenshot](022.png)
![lab Screenshot](023.png)

Create a custom rule
![Lab Screenshot](025.png)
![Lab Screenshot](026.png)
![Lab Screenshot](027.png)
![Lab Screenshot](028.png)


<details><summary>What is the fifth flag you receive after successfully detecting sample5.exe?</summary>
![Lab Screenshot](029.png)
THM{46b21c4410e47dc5729ceadef0fc722e}</details>

Question 6.

Let's see the attached file: commands.log
![Lab Screenshot](030.png)

Submit the sample6.exe file for Analys
![Lab Screenshot](031.png)
![Lab Screenshot](032.png)
![LAb Screenshot](033.png)

Create a custom rule
![Lab Screenshot](034.png)
![Lab Screenshot](035.png)
![Lab Screenshot](036.png)

![Lab Screenshot](037.png)

<details><summary>What is the final flag you receive from Sphinx?</summary>

![Lab Screenshot](038.png)
THM{c8951b2ad24bbcbac60c16cf2c83d92c}</details>