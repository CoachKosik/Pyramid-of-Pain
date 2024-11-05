# Pyramid of Pain - Investigate a suspicious file hash

## Objective

In this activity, you'll analyze an artifact using VirusTotal and capture details about its related indicators of compromise using the Pyramid of Pain.  

The Pyramid of Pain, which is used to understand the different types of indicators of compromise (IoCs). An IoC is observable evidence that suggests signs of a potential security incident. The Pyramid of Pain describes the relationship between IoCs and the level of difficulty that malicious actors experience when the IoCs are blocked by security teams.

VirusTotal is one of many tools that security analysts use to identify and respond to security incidents. VirusTotal is a service that allows anyone to analyze suspicious files, domains, URLs, and IP addresses for malicious content. Through crowdsourcing, VirusTotal gathers and reports on threat intelligence from the global cybersecurity community. This helps security analysts determine which IoCs have been reported as malicious. As a security analyst, you can take advantage of shared threat intelligence to learn more about threats and help improve detection capabilities. 

## Project description

You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 

You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

You retrieve the malicious file and create a SHA256 hash of the file. You might recall from a previous course that a hash function is an algorithm that produces a code that can't be decrypted. Hashing is a cryptographic method used to uniquely identify malware, acting as the file's unique fingerprint. 

Now that you have the file hash, you will use VirusTotal to uncover additional IoCs that are associated with the file.

## Skills Learned
This lab focused on utilizing VirusTotal for threat intelligence gathering and identifying Indicators of Compromise (IoCs) associated with a suspicious file. Here are the specific skills learned:

Threat Intelligence Gathering:
  * Understanding the purpose of VirusTotal and its role in threat intelligence sharing.
  * Identifying relevant information from VirusTotal reports, including detection rates, community scores, and sandbox reports.
  * Using a VirusTotal report to investigate suspicious files and gather details about their potential maliciousness.

Indicator of Compromise (IoC) Identification:
  * Understanding the different types of IoCs (hash values, IP addresses, domain names, network/host artifacts, tools, TTPs).
  * Utilizing VirusTotal reports to identify various IoCs associated with a suspicious file.
  * Locating relevant information within different sections of a VirusTotal report (Details, Relations, Behavior) to find specific IoCs.

Security Incident Investigation:
  * Applying VirusTotal findings to determine the potential maliciousness of a suspicious file.
  * Recognizing patterns and trends within VirusTotal reports to support conclusions about a file's threat level.
  * Building a picture of the potential attack by identifying related IoCs using VirusTotal.

Critical Thinking and Analysis:
  * Evaluating information from VirusTotal reports with a critical eye, considering the source and context.
  * Correlating data from different sections of a VirusTotal report to draw informed conclusions.
  * Making informed decisions about the potential maliciousness of a file based on available evidence.

## Tools Used
* **SHA256 file hash**
* **<a href="https://www.virustotal.com/gui/home/upload">VirusTotal Website</a>**
* **"Pyramid of Pain" conceptual framework:** used in cybersecurity to illustrate the different levels of indicators of compromise (IoCs) and their relative value to defenders.

## Steps
### Step 1: Access the template
To use the template for this course item, click the link below and select Use Template.
  * Link to template: <a href="https://docs.google.com/presentation/d/1s8zt0uWIZEz8BeR_esOvrK5u0FGy7ij3/edit?usp=sharing&ouid=105064495821226407439&rtpof=true&sd=true">Pyramid of Pain</a>

### Step 2: Review the details of the alert
The following information contains details about the alert that will help you complete this activity. The details include a file hash and a timeline of the event. Keep these details for reference as you proceed to the next steps.

**SHA256 file hash:** 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

Here is a timeline of the events leading up to this alert:
  * 1:11 p.m.: An employee receives an email containing a file attachment.
  * 1:13 p.m.: The employee successfully downloads and opens the file.
  * 1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.
  * 1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.


### Step 3: Enter the file has into VirusTotal
Go to the <a href="https://www.virustotal.com/gui/home/upload">VirusTotal Website</a>. Click **SEARCH**, enter the SHA256 file hash in the search box, and press enter. The SHA256 file hash is listed in Step 2 of this activity.

### Step 4: Analyze the VirusTotal report
Once you've retrieved VirusTotal's report on the file hash, take some time to examine the report details. You can start by exploring the following tabs:
  * **Detection:** This tab provides a list of third-party security vendors and their detection verdicts on an artifact. Detection verdicts include: malicious, suspicious, unsafe, and others. Notice how many security vendors have reported this hash as malicious and how many have not.
    * ![virus total 1](https://github.com/user-attachments/assets/b0879127-2c47-48a9-951d-2dad6d99a8a4)
  * **Details:** This tab provides additional information extracted from a static analysis of the IoC. Notice the additional hashes associated with this malware like MD5, SHA-1, and more.
    * ![virus total 2](https://github.com/user-attachments/assets/975b3060-fac3-4c72-959f-52f9b1f08511)
  * **Relations:** This tab contains information about the network connections this malware has made with URLs, domain names, and IP addresses. The Detections column indicates how many vendors have flagged the URL or IP address as malicious.
    * ![virus total 3](https://github.com/user-attachments/assets/e89d8fb3-3e70-4038-94fd-8fd291a4c94e)
  * **Behavior:** This tab contains information related to the observed activity and behaviors of an artifact after executing it in a controlled environment, such as a sandboxed environment. A sandboxed environment is an isolated environment that allows a file to be executed and observed by analysts and researchers. Information about the malware's behavioral patterns is provided through sandbox reports. Sandbox reports include information about the specific actions the file takes when it's executed in a sandboxed environment, such as registry and file system actions, processes, and more. Notice the different types of tactics and techniques used by this malware and the files it created.
    * ![virus total 4](https://github.com/user-attachments/assets/f3a1862a-20c8-4c19-bd8c-89398c77bff6)

### Step 5: Determine whether the file is malicious
Review the VirusTotal report to determine whether the file is malicious. The following sections will be helpful to review before making this determination:
  * The **Vendors' ratio** is the metric widget displayed at the top of the report. This number represents how many security vendors have flagged the file as malicious over all. A file with a high number of vendor flags is more likely to be malicious.
  * The **Community Score** is based on the collective inputs of the VirusTotal community. The community score is located below the vendor's ratio and can be displayed by hovering your cursor over the red X. A file with a negative community score is more likely to be malicious.
    * ![virus total 5](https://github.com/user-attachments/assets/a941ecc6-7122-4569-b300-194f14434620)
  * Under the **Detection** tab, the **Security vendors' analysis** section provides a list of detections for this file made by security vendors, like antivirus tools. Vendors who have not identified the file as malicious are marked with a checkmark. Vendors who have flagged the file as malicious are marked with an exclamation mark. Files that are flagged as malicious might also include the name of the malware that was detected and other additional details about the file. This section provides insights into a file's potential maliciousness.
    * ![virus total 6](https://github.com/user-attachments/assets/9ce88663-c23c-4b7e-aa12-e98c3cda0d66)

Review these three sections to determine if there is a consistent assessment of the file's potential maliciousness such as: a high vendors' ratio, a negative community score, and malware detections in the security vendors' analysis section. 

In the first slide of your Pyramid of Pain template, indicate whether this file is malicious. Then, explain your reasoning based on your findings.
  * Has this file been identified as malicious? Explain why or why not.
    * Yes, the file hash has been reported as malicious. Over 81% of the vendors have flagged the file, and it has a negative community score of -208. Additionally, this file hash is associated with the known malware Flagpro, which is commonly used by the advanced threat actor BlackTech.

### Step 6: Fill in the template with additional indicators of compromise (IoC)
After you've explored the sections in the VirusTotal report, you will uncover additional IoCs that are associated with the file according to the VirusTotal report.

Identify three indicators of compromise (IoCs) that are associated with this file hash using the tabs in the VirusTotal report. Then, enter the IoCs into their respective sections in the <a href="https://docs.google.com/presentation/d/1s8zt0uWIZEz8BeR_esOvrK5u0FGy7ij3/edit?usp=sharing&ouid=105064495821226407439&rtpof=true&sd=true">Pyramid of Pain</a> template.

Indicators of compromise are valuable sources of information for security professionals because they are used to identify malicious activity. You can choose to identify any three of the six types of IoCs found in the Pyramid of Pain: 

  * **Hash value:** Hashes convert information into a unique value that can't be decrypted. Hashes are often used as unique references to files involved in an intrusion. In this activity, you used a SHA256 hash as the artifact for this investigation. Find another hash that's used to identify this malware and enter it beside the Hash values section in the Pyramid of Pain template. You can use the Details tab to help you identify other hashes.
  * **IP address:** Find an IP address that this malware contacted and enter it beside the IP addresses section in the Pyramid of Pain template. You can locate IP addresses in the Relations tab under the Contacted IP addresses section or in the Behavior tab under the IP Traffic section.
  * **Domain name:** Find a domain name that this malware contacted and enter it beside the Domain names section in the Pyramid of Pain template. You can find domain name information under the Relations tab. You might encounter benign domain names. Use the Detections column to identify domain names that have been reported as malicious.
  * **Network artifact/host artifact:** Malware can create network-related or host-related artifacts on an infected system. Find a network-related or host-related artifact that this malware created and enter it beside the Network/host artifacts section in the Pyramid of Pain template. You can find this information from the sandbox reports under the Behavior tab or from the Relations tab.
  * **Tools:** Attackers can use tools to achieve their goal. Try to find out if this malware has used any tool. Then, enter it beside the Tools section in the Pyramid of Pain template.
  * **Tactics, techniques, and procedures (TTPs):** TTPs describe the behavior of an attacker. Using the sandbox reports from the Behavior tab, find the list of tactics and techniques used by this malware as identified by MITRE ATT&CK® and enter it beside the TTPs section in the Pyramid of Pain template. 

### Summary
This lab exercise focused on utilizing VirusTotal and the Pyramid of Pain framework to analyze a suspicious file and identify associated Indicators of Compromise (IoCs). By leveraging VirusTotal, you were able to assess the file's maliciousness based on vendor detections, community scores, and sandbox analysis. This exercise enhanced your understanding of threat intelligence, IoC identification, and the importance of utilizing tools like VirusTotal in security investigations.
