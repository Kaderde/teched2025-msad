[![REUSE status](https://api.reuse.software/badge/github.com/sap-samples/teched2023-XP185v)](https://api.reuse.software/info/github.com/sap-samples/teched2023-XP185v)


# Mastering Secure Application Development in SAP BTP : A Practical Workshop

## Description

This repository contains the material for the **Mastering Secure Application Development in SAP BTP: A Practical Workshop** session.  

## Overview

Welcome to this hands-on workshop dedicated to embedding security into your SAP BTP applications. 
In an era where data breaches and cyber threats are constant, building secure software is not an option—it's a requirement. This lab is designed for developers working with the SAP Cloud Application Programming Model (CAP) and Node.js. 

By completing the exercises, you will gain the practical skills to identify and mitigate common security risks as defined by the [OWASP Top 10 vulnerabilities](https://owasp.org/Top10/). 

### 🎯 Learning Objectives

-	**Identify and Mitigate** a critical OWASP Top 10 vulnerability in a real-world scenario.
-	**Leverage**  the SAP Cloud Application Programming Model (CAP) for secure, cloud-native development.
-	**Implement** BTP's comprehensive, built-in security services to protect your data and business logic.
-	**Validate** the effectiveness of security fixes through practical testing.

<p align="center">
  <img src="img/top10-owasp.png" alt="Top 10 OWASP Vulnerabilities" width="900"/>
  <br>
  <b>Top 10 OWASP Vulnerabilities</b>
</p>

## Requirements (TBD)

The requirements to follow the exercises in this repository are active trial accounts for SAP BTP and for the SAP Cloud Identity Services. 

**First you have to get your SAP BTP trial account. Follow these instructions and choose the region "US East (VA)":** 
[Get a Free Account on SAP BTP Trial](https://developers.sap.com/tutorials/hcp-create-trial-account.html)

**Then activate your SAP Cloud Identity Services trial. Follow the instructions in this blog:** 
[SAP Cloud Identity Services offered as Trial Version](https://blogs.sap.com/2023/04/13/sap-cloud-identity-services-offered-as-trial-version/)
💡Ensure that you choose the default domain "ondemand.com", as "cloud.sap" is currently not supported on the trial landscape.

💡You should have access to your mailbox, which you used while registering for your BTP trial account in order to activate your SAP Cloud Identity Services trial account.

**Finally, install a Time-based One-Time-Password (TOTP) authentication application (such as Google Authenticator or Microsoft Authenticator) on your mobile device and familiarize yourself with the process to create accounts in the app.**

Now you are ready to start the exercises.

💡In some of the exercises you will be asked to switch from one user to another. This works more reliable if you use the Incognito mode of your browser. Without the Incognito mode, you may run into situations where you are authenticated automatically with the wrong user.

## Exercises
Every exercise module is a self-contained lab focused on a specific vulnerability. All modules adhere to the following standard structure:

- 📖 **Overview:** A high-level description of the vulnerability, its impact, and why it's a security risk.
- 🚨 **Vulnerable Code:** A snippet of code containing the specific security flaw. We'll analyze why it's insecure.
- 💥 **Exploitation:** A step-by-step guide on how to exploit the vulnerability, demonstrating its real-world impact.
- 🛡️ **Remediation:** The corrected version of the code that patches the vulnerability, along with an explanation of the fix.
- ✅ **Verification:** A simple procedure to confirm that the patch has successfully mitigated the vulnerability and the exploit no longer works.
- 📌 **Summary:** A practical recap that consolidates the exercise outcomes with actionable takeaways.

This structure is designed to help you understand a vulnerability from an attacker's perspective and a defender's, see how it can impact a CAP application, and learn actionable steps to mitigate it with BTP best practices. 

- [Getting Started](exercises/ex0/) (TBD)

- [Exercise 1 - Broken Access Control](exercises/ex1/)
    - [Exercise 1.1 - Horizontal Privilege Escalation](exercises/ex1/ex1.1/README.md)
    - [Exercise 1.2 - Vertical Privilege Escalation](exercises/ex1/ex1.2/README.md)
  
- [Exercise 2 - SQL injection](exercises/ex2/)

- [Exercise 3 - Security Logging and Monitoring Failures](exercises/ex3/)
    - [Exercise 3.1 - Audit Logging in CAP](exercises/ex3/README.md)
    - [Exercise 3.2 - Setting up SAP Audit] log (exercises/ex3/README.md)

Otpional exercises :
- [Exercise 1.4 - Insecure Direct Object References (IDOR)](exercises/ex1/ex1.3/README.md)
    

**IMPORTANT**

Your repo must contain the .reuse and LICENSES folder and the License section below. DO NOT REMOVE the section or folders/files. Also, remove all unused template assets (images, folders, etc) from the exercises folder. 

## Contributing
Please read the [CONTRIBUTING.md](./CONTRIBUTING.md) to understand the contribution guidelines.

## Code of Conduct
Please read the [SAP Open-Source Code of Conduct](https://github.com/SAP-samples/.github/blob/main/CODE_OF_CONDUCT.md).

## How to obtain support

Support for the content in this repository is available during the actual time of the online session for which this content has been designed. Otherwise, you may request support via the [Issues](../../issues) tab.

## License
Copyright (c) 2025 SAP SE or an SAP affiliate company. All rights reserved. This project is licensed under the Apache Software License, version 2.0 except as noted otherwise in the [LICENSE](LICENSES/Apache-2.0.txt) file.
