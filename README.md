# PRODIGY_CS_04

Task 04: Keylogger Detection and Mitigation.

This is a Python project for the Prodigy InfoTech Cyber Security Internship. The program simulates process monitoring to detect potential keyloggers and other malware.


It flags processes based on two main criteria: suspicious names and high resource usage.

Key features:

The tool uses the psutil library to access system process information (PID, Name, CPU %, Memory %).

It maintains a watchlist of common malicious names (like "keylogger" or impersonated names like "svchost").

It monitors for processes consuming excessive CPU or memory, indicating potentially malicious activity.

It provides an immediate alert to the user, recommending manual investigation.

Technology used:

Python

psutil library

This project provides practical knowledge of endpoint security and system monitoring.
