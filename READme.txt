ScanSense: TCP Port Scan Attack Detection Tool
ScanSense is a comprehensive network scanning and attack detection tool developed using Python. It utilizes artificial intelligence (AI) techniques, specifically machine learning, to detect TCP port scan attacks within a network.
Table of Contents
•	Introduction
•	Features
•	Installation
•	Usage
•	License
Introduction
TCP port scan attacks are commonly used by hackers to probe network systems for vulnerabilities. Detecting and preventing these attacks can be challenging, but ScanSense leverages AI techniques to enhance attack detection. By utilizing the Scapy library, ScanSense performs port scanning, identifies open ports, and determines associated services within a target IP address.
One of the key aspects that sets ScanSense apart is its integration of machine learning. It incorporates a machine learning model based on the random forest classifier, trained on a preprocessed dataset of normalized network data. This training enables the model to classify the presence of attacks based on patterns of open ports detected during a scan.
Features
•	TCP port scan attack detection using machine learning techniques
•	User-friendly interface for network administrators and security professionals
•	Comprehensive network scanning functionality
•	Identification of live hosts within a specified IP address range
•	Detection of potential security threats and malicious activities
Installation
To install and run ScanSense, follow these steps:
1.	Clone the repository: git clone https://github.com/your-repo/ScanSense.git
2.	Navigate to the project directory: cd ScanSense
3.	Install the required dependencies: pip install -r requirements.txt
Usage
To use ScanSense, follow these steps:
1.	Run the tool: python scansense.py
2.	Select the desired scanning mode: individual IP address scanning or network scanning
3.	Follow the on-screen instructions to provide the necessary input parameters
4.	ScanSense will perform the port scan and display the results, indicating potential TCP port scan attacks
License
Feel free to customize this README file based on your project's specific requirements and guidelines.

