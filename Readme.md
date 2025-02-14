Easy Guide: Integrate Snort with Splunk for Real-Time Intrusion Detection
Shobinmendez

Shobinmendez
12 min read
·
Just now
1. Introduction
What is Snort?

Snort is an open-source network intrusion detection system (IDS) that analyzes network traffic in real-time, looking for suspicious activities and potential security breaches.
What is Splunk?

Splunk is a powerful platform for monitoring, searching, analyzing, and visualizing machine data. Integrating Snort with Splunk allows us to centralize IDS logs and gain actionable insights.
Requirements and Prerequisites

Before we start, let’s make sure you have everything you need.
1. Hardware & Software Requirements

You’ll need two computers:
I. A Linux Machine (Ubuntu 20.04 recommended) — This will run Snort (a tool that detects suspicious network activity) and the Splunk Universal Forwarder (which sends Snort logs to Splunk).
II. A Windows Machine — This will run Splunk Enterprise, which helps you monitor and analyze logs.
2. Network Setup

📡 Ensure both machines are on the same network so they can communicate.

    If you’re using a Virtual Machine (VM) like VirtualBox, set the network to Bridged Mode so it behaves like a real machine on your network.

Check your Ubuntu machine’s IP address using:

ip a

Write this IP down! You’ll need it later.
3. Software You Need to Install

You’ll need to install:
✅ Snort — Monitors network traffic and detects threats.
✅ Splunk Universal Forwarder — Sends Snort logs to Splunk Enterprise.
✅ Splunk Enterprise (on Windows) — Displays and analyzes the logs.
4. Basic Knowledge Required

Don’t worry if you’re not an expert! Just be familiar with:
✅ Basic Linux commands (like sudo apt update)
✅ How networks work (IP addresses, ports)
Installing Snort on Ubuntu (Step-by-Step Guide for Beginners!)
🛠 Step 1: Update Your System

Before installing anything, make sure your system is up to date.

Open the Terminal on your Ubuntu machine and run:

sudo apt update && sudo apt upgrade -y

Step 2: Install Dependencies

Before installing Snort, we need to install some necessary tools and libraries that help it run properly.
Install Required Packages

Run the following command:

sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev

What These Packages Do:

    build-essential – Contains tools to compile and build software.
    libpcap-dev – Helps Snort capture network packets.
    libpcre3-dev – Supports pattern matching (used in Snort rules).
    libdnet-dev – Provides low-level networking functions.
    zlib1g-dev – Compresses logs efficiently.
    luajit & libluajit-5.1-dev – Enables scripting in Snort.
    libssl-dev – Provides encryption support.
    libnghttp2-dev – Supports HTTP/2 connections.
    liblzma-dev – Another compression library.

Verify Installation

Once the installation is complete, you can check if everything was installed correctly by running:

dpkg -l | grep -E "libpcap|libpcre3|libdnet|zlib1g|luajit|libssl|libnghttp2|liblzma"

Step 3: installing snort

Now that we’ve installed the required dependencies, let’s move on to installing Snort itself. Since Snort is not included in Ubuntu’s official package manager, we need to download, compile, and install it manually.

apt-get install snort -y

What This Does:

    sudo – Runs the command with administrator (root) privileges.
    apt-get install snort – Downloads and installs Snort along with its required dependencies.
    -y – Automatically confirms installation without asking for permission.

While installing snort we will be asked to which interface should snort listen. We need to mention the interface when the popup is appeared for this we need to know what our Ubuntu IP is , we can use command <IP a> this shows the interface as :

in this my IP interface is enp0s3 add this in the configuration prompt appear while installing snort.
Step 5: Verify Snort Installation

Run the following command to check the version:

snort -V

Configuring Snort

Step 1: Define Your Network Variables

We need to tell Snort which network to monitor by setting HOME_NET and EXTERNAL_NET.
Open the Snort Configuration File

Run the following command to open snort.conf in a text editor:

sudo nano /etc/snort/snort.conf

Scroll down to find the section that defines the network variables (around line 45–50). It should look like this:

# Setup the network addresses you are protecting
ipvar HOME_NET any

Change it to match your network

If you know your local network’s IP range (e.g., 192.168.1.6/24), modify it like this:

ipvar HOME_NET 192.168.1.0/24

Explanation:

    HOME_NET – Defines the network you want to protect.
    EXTERNAL_NET – Defines the outside network (potential attackers).

Enable Snort Rule Sets

Snort detects threats using rules stored in /etc/snort/rules/.
Check the Available Rules

Run the following command:

ls /etc/snort/rules/

You should see files like:
Enable Rule Files in snort.conf

Go back to editing snort.conf

Scroll down to the section where rule files are listed (around line 550). You’ll see lines like:

Step 2: Add Custom Rules

Open the local.rules file to add rules:

sudo nano /etc/snort/rules/local.rules

Adding simple rules like:

ICMP rule:

    alert icmp any any -> any any (msg:”ICMP Packet detected”; sid:1000001; rev:1;)

    alert → Triggers an alert when the rule is matched.
    icmp → Detects ICMP (ping) packets.
    any any -> any any → Matches ICMP traffic from any source to any destination.
    msg:"ICMP Packet detected" → Displays this message when triggered.
    sid:1000001; → Unique rule ID.
    rev:1; → Rule version (increase when updating the rule).

📌 Purpose: Detects and alerts on any ICMP (ping) traffic in the network.

SSH rule:

    alert tcp any any -> $HOME_NET 22 (msg:”Successful SSH Login Detected”; flags:PA; sid:100002; rev:3;)

    alert → Triggers an alert when the rule is matched.
    tcp → Monitors TCP traffic (SSH uses TCP).
    any any -> $HOME_NET 22 → Matches traffic from any source to port 22 (SSH) on the home network.
    flags:PA; → Detects packets with Push (P) and Acknowledgment (A) flags, indicating an established SSH session (successful login).
    msg:"Successful SSH Login Detected" → Displays this alert message.
    sid:100002; → Unique rule ID.
    rev:3; → Rule version (increase when modifying).

Purpose:

This rule alerts only on successful SSH logins, not just connection attempts

Command Execution rule:

    alert tcp any any -> $HOME_NET any (msg:”Command Execution Attempt”; content:”GET”; content:”/etc/passwd”; sid:100003; rev:2;)

    alert → Triggers an alert when the rule is matched.
    tcp → Monitors TCP traffic.
    any any -> $HOME_NET any → Matches traffic from any source to any destination in the home network on any port.
    content:"GET"; → Looks for HTTP GET requests (used in web-based attacks).
    content:"/etc/passwd"; → Detects attempts to access the /etc/passwd file (which stores user account details on Linux).
    sid:100003; → Unique rule ID.
    rev:2; → Rule version (increase when modifying the rule).

Purpose:

Detects potential remote command execution (RCE) attacks where an attacker tries to read sensitive system files via a web request.

Telnet Detection Rule

    alert tcp any any -> any 23 (msg:”Telnet Connection Detected”; sid:1000001;)

    alert Triggers an alert when the rule is matched.tcpMonitors TCP traffic (Telnet runs on TCP).any any Matches traffic from any IP address and any port (source).->Indicates the traffic direction (from source to destination).any 23Matches traffic going to any IP address on port 23 (Telnet).msg:"Telnet Connection Detected";Displays the message "Telnet Connection Detected" in logs when triggered.sid:1000001;Unique rule ID (used to track and manage the rule in Snort).

Purpose:

This rule detects any Telnet connection attempt by monitoring traffic on port 23, which is commonly used for Telnet communication. It helps in identifying unauthorized or unexpected Telnet activity in the network.

NMAP rule:

    alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:”Nmap TCP Connect Scan”; flags:S,12; threshold:type both, track by_src, count 20, seconds 60; sid:100008; rev:1;)

    alert → Triggers an alert when the rule is matched.
    tcp → Monitors TCP traffic.
    $EXTERNAL_NET any -> $HOME_NET any → Matches traffic from any external source to any port in the home network.
    flags:S,12; → Detects packets with the SYN flag set, which indicates a connection attempt (used in Nmap scans).
    threshold:type both, track by_src, count 20, seconds 60; → Limits alerts to 20 connection attempts from the same source within 60 seconds (helps avoid false positives).
    sid:100008; → Unique rule ID.
    rev:1; → Rule version (increase when modifying).

Purpose:

Detects Nmap TCP Connect scans, where an attacker tries to discover open ports on a target system.
4. Testing Snort Rules Locally

    Run Snort in Logging Mode:

sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf

2. Send an ICMP Request (Ping): Use ping from an attacker machine (or another machine in the network) to generate an ICMP packet and send it to the target system.

Example command:

ping <target ip>

Replace <Target_IP_Address> with the IP address of the machine running Snort.

This will send a single ICMP Echo Request (ping) to the target.

Check Snort Alerts: After sending the ping, Snort should detect the ICMP traffic. In your Snort terminal output, you should see an alert message similar to:

3.Brute-Force SSH Connection from Attacker Machine: You can simulate an SSH brute-force attack using a tool like Hydra or Medusa to repeatedly attempt to log in to the target system over SSH.

Example with Hydra:

hydra -l username -P /path/to/passwords.txt ssh://<Target_IP_Address>

    -l username: Replace username with a valid username on the target machine.
    -P /path/to/passwords.txt: Replace /path/to/passwords.txt with the path to a file containing a list of passwords (common passwords or a dictionary list).
    ssh://<Target_IP_Address>: Replace <Target_IP_Address> with the actual IP address of the target machine (the one running SSH).

This command will attempt to brute-force SSH login using the password list. If you have an SSH server running on the target machine, this will try many login combinations.

Monitor Snort Alerts: Snort should detect any successful SSH connection attempts and trigger an alert based on the rule.

In your Snort output, look for an alert similar to this:

Verify the Rule: You should see the message “Successful SSH Login Detected” in the Snort alert when a successful SSH login happens during the brute-force attempt.
Important Notes:

    Test Setup: Ensure that SSH is running on the target system and that the target machine’s firewall is configured to allow SSH traffic on port 22.
    Brute-Force Tools: Hydra is a common tool for this purpose, but make sure you’re testing in a controlled environment and have permission to conduct security tests on the system.
    Alerts in Snort: If the rule is configured correctly, Snort will detect the connection and generate an alert for each successful SSH login attempt.

4. Simulate a Command Execution Attack (GET Request): In this scenario, we will send a GET request containing /etc/passwd (which is commonly targeted for reading by attackers).

You can use curl to simulate the attack from the attacker machine:

curl "http://<Target_IP_Address>/etc/passwd"

Replace <Target_IP_Address> with the actual IP address of the target machine (the machine running the web server or a vulnerable service).

This GET request attempts to access the /etc/passwd file, which is often targeted in web-based attacks like Local File Inclusion (LFI).

Monitor Snort Alerts: After sending the malicious GET request, Snort should trigger the alert based on the rule you defined. You should see an alert in Snort like:

This alert indicates that Snort detected a command execution attempt based on the GET request for /etc/passwd.

Verify the Rule Activation: If the rule is properly configured, Snort will alert you whenever it detects the specified /etc/passwd in the HTTP request, indicating a potential command execution attempt.
Important Notes:

    This test assumes you have a vulnerable web application or service where an attacker can try to execute such commands via a URL.
    Ensure that you’re testing this on a controlled environment (such as a test server), as testing on production systems could cause unintended consequences.

6. Simulate an Nmap Scan from Attacker Machine: On the attacker machine (or any machine in the same network), use Nmap to perform a TCP Connect scan. This will simulate a basic port scan that Nmap performs.

Example command to run the scan:

nmap <target ip> -p-

Replace <Target_IP_Address> with the actual IP address of the target machine (the one running Snort).

Monitor Snort Alerts: After running the Nmap scan, Snort should detect the scanning activity and trigger the Nmap scanning detection rule. You should see an alert similar to:

Verify the Rule Activation: If the rule is configured correctly, Snort should generate an alert whenever Nmap attempts to scan a set of ports on the target machine, matching the specified threshold (in your case, 20 connection attempts in 60 seconds).
Important Notes:

    Nmap Scans: Nmap has several types of scans, such as SYN scans, UDP scans, TCP connect scans, etc.. The rule you configured specifically looks for TCP Connect scans (-sT), which are slower but easy to detect.
    Thresholds: If you’re running the Nmap scan on multiple ports within a short period (e.g., 20 connection attempts in 60 seconds), the alert will trigger based on the threshold settings in the rule.
    Test Environment: Make sure you’re testing in a controlled environment (e.g., a testing lab) to avoid disrupting live systems or networks.

5. Configuring Splunk Enterprise to Receive Snort Logs

To configure Splunk Enterprise to receive Snort logs, you need to follow these steps carefully to ensure that Snort logs are properly forwarded to Splunk for monitoring. This involves setting up the Splunk Universal Forwarder (on your Snort server) to forward the logs to Splunk Enterprise (on your Windows machine).
1. Create an Index for Snort Logs in Splunk Web

To store Snort logs separately in Splunk, you need to create an index.
Steps:

    Login to Splunk Web
    Open your browser and go to:

    http://<SPLUNK_SERVER_IP>:8000

2.Navigate to Index Management:

    Click on Settings (⚙️) → Indexes.
    Click New Index (top-right corner).

3.Create a New Index for Snort Logs:

    Index Name: snort
    Datatype: Events
    Home Path: “C:\Program Files\Splunk\var\lib\splunk\snort”
    Cold Path: “C:\Program Files\Splunk\var\lib\splunk\snort\colddb”
    Max Size: Default (or specify based on your need)
    Click Save.

2. Configure Splunk to Receive Logs from Snort

Snort logs are typically stored in /var/log/snort/. We need to configure Splunk Universal Forwarder to monitor this directory.
Steps on the Ubuntu Server Running Snort:

    Ensure Splunk Forwarder is Installed and Running:

sudo /opt/splunkforwarder/bin/splunk status

splunk is running properly. If it is inactive run it using this command:

sudo /opt/splunkforwarder/bin/splunk start

2. Add the Snort Log File for Monitoring:

sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/snort/ -index snort -sourcetype snort

3. Restart the Forwarder to Apply Changes:

sudo /opt/splunkforwarder/bin/splunk restart

4. Verify Logs in Splunk

Check if Logs Are Being Received

    Go to Splunk Web and open the Search & Reporting App.
    Run the following search query:

    index=snort sourcetype=snort

5. Verifying customs rule that detected on splunk.
