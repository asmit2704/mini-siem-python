# Mini SIEM Detection & Alerting Platform

## Overview

This project simulates a basic Security Information and Event Management (SIEM) platform built in Python. The system ingests log data, applies detection rules, generates security alerts, maps detections to MITRE ATT&CK techniques, and produces incident reports.

The goal of the project is to demonstrate how SOC analysts and detection engineers identify suspicious activity from security logs.

## Features

* Log Parsing
* Detection Rule Engine
* Alert Generation
* Severity Classification
* MITRE ATT&CK Mapping
* Incident Report Generation

## Project Architecture

Logs
↓
Detection Rules
↓
Alert Engine
↓
Incident Report

## Detection Rules

### SSH Brute Force Detection

Detects repeated failed SSH authentication attempts from the same source IP address.

### User Creation Detection

Detects Windows Event ID 4720 indicating a newly created user account.

### Administrative Login Detection

Detects Windows Event ID 4672 indicating privileged account activity.

## MITRE ATT&CK Mapping

| Detection Rule       | MITRE Technique |
| -------------------- | --------------- |
| SSH Brute Force      | T1110           |
| User Creation        | T1136           |
| Administrative Login | TA0004          |

## Sample Alerts

* SSH Brute Force Attack
* New User Account Created
* Administrative Privilege Assignment

## Screenshots

* Folder Structure
* Detection Rule Code
* Alert Dashboard Output
* Generated Incident Report

## Skills Demonstrated

* Security Monitoring
* Detection Engineering
* Threat Detection
* Log Analysis
* Incident Reporting
* MITRE ATT&CK Mapping
* Python Automation

## Future Improvements

* Real Windows Event Logs
* Linux Syslog Integration
* JSON Alert Export
* CSV Reporting
* Splunk Integration
* Wazuh Integration
* Email Notifications
* Web Dashboard

## Outcome

Successfully built a Python-based SIEM prototype capable of parsing logs, detecting suspicious events, generating alerts, and producing incident reports.
