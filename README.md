Log Analysis Script
Overview
This Python script processes log files to extract and analyze key information. It performs the following tasks:

Count Requests per IP Address: Counts the number of requests made by each IP address.
Identify the Most Frequently Accessed Endpoint: Identifies the endpoint accessed the highest number of times.
Detect Suspicious Activity: Flags IP addresses with excessive failed login attempts (e.g., status code 401 or a failure message like "Invalid credentials").
Output Results: Displays the results in the terminal and saves them to a CSV file for further analysis.
This script is useful for analyzing web server logs, detecting suspicious activities like brute-force login attempts, and understanding user behavior.

Features
Count requests per IP address and display them in descending order.
Identify the most accessed endpoint.
Flag suspicious activity based on failed login attempts.
Display results in the terminal and save them to a CSV file.
Requirements
Python 3.x
No additional libraries required (the script uses built-in Python modules).
Setup
Clone this repository to your local machine.

bash
Copy code
git clone https://github.com/your-username/log-analysis-script.git
Navigate to the project directory.

bash
Copy code
cd log-analysis-script
Ensure that you have a log file (e.g., sample.log) in the same directory as the script, or update the path to the log file in the script.

Usage
Save your log data into a file named sample.log (or update the script with your log file name).

Run the script:

bash
Copy code
python log_analysis_script.py
The script will:

Display the IP request counts, most accessed endpoint, and suspicious activity in the terminal.
Save the results to a CSV file named log_analysis_results.csv.
Output
The script will output the following results to the terminal:

#Example Terminal Output
IP Address           Request Count
203.0.113.5         8
198.51.100.23       8
192.168.1.1         7
10.0.0.2            6
192.168.1.100       5

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
203.0.113.5         8


#Example CSV Output (log_analysis_results.csv)
Requests per IP
IP Address,Request Count
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
10.0.0.2,6
192.168.1.100,5

Most Accessed Endpoint
Endpoint,Access Count
/login,13

Suspicious Activity
IP Address,Failed Login Count
203.0.113.5,8
