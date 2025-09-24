# Exercise 2.1 - SQL injection
Vulnerability: A03:2021-Injection

## 📖  1. Overview :

This exercise demonstrates how unsanitized user inputs can be exploited to perform SQL Injection attacks, thereby compromising the integrity and confidentiality of enterprise data. In the Incident Management system, input fields—such as those accepting credit card numbers—are vulnerable if not properly validated. As a result, attackers can inject malicious SQL code into these fields, leading to unauthorized data access or manipulation without triggering adequate security alarms.

### 📐Business Rules

* Support Users:
  - ✅ Can view customer data.
  - ✅ Can view, create, update, and delete incidents (with restrictions on closed/high-urgency incidents).
  - ❌ Cannot access customers sensitive data (e.g., credit card numbers).
  - ⚠️ All access attempts must be logged (e.g., who accessed/modified which incident, when.

* Administrators:
  - ✅ Full access to customer and incidents data.
  - ⚠️ All operations, including access to sensitive fields, are logged for audit compliance.

### 🎯 Key Learning Objectives

* Implement object-level authorization, data masking, and audit logging
* Ensure users only access customer data they are authorized to view.
* Maintain comprehensive records of access.
* Protect sensitive information and mitigate unauthorized data exposure risks.

