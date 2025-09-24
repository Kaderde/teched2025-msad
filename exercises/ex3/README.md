# Exercise 3 - SQL injection
Vulnerability: A03:2021-Injection

## 📖  1. Overview :

This exercise demonstrates how unsanitized user inputs can be exploited to perform SQL Injection attacks, thereby compromising the integrity and confidentiality of enterprise data. In the Incident Management system, input fields—such as those accepting credit card numbers—are vulnerable if not properly validated. As a result, attackers might inject malicious SQL code to retrieve, alter, or delete sensitive records without detection.

### 📐Business Rules

  - ❌ Users Must not exploit insecure input fields to inject or modify SQL queries.
  - ⚠️ All user inputs must be rigorously validated and sanitized to prevent SQL Injection.

### ⚠️ Why This Matters

 * **Business Impact:** Successful SQL Injection attacks can compromise the integrity and confidentiality of critical data, leading to unauthorized data disclosure, manipulation, or deletion.
 * **Compliance Risk:** Violates [OWASP Top 10 A03](https://owasp.org/Top10/A03_2021-Injection/) and GDPR/PCI DSS requirements for input validation.
 * **Security Risk:** Malicious actors could exfiltrate sensitive data (e.g., credit card numbers) or bypass authorization controls.

### 🎯 Key Learning Objectives

- Understand the mechanics of SQL Injection and how unsanitized inputs can be exploited.
- Learn to implement secure coding practices, such as parameterized queries, to mitigate SQL Injection vulnerabilities.
- Ensure that application data remains secure, protecting sensitive information from unauthorized access or alteration.

## 🚨 2. Vulnerable Code :
We’ll build upon [Exercise 2.2 - Security Event Monitoring](../ex2/ex2.2/README.md)  by introducing an SQL Injection vulnerability resulting from unsanitized user input.

Here's the modified services.js file with an added SQL Injection vulnerability demonstration. 
The vulnerability is introduced in a new fetchIncident method that directly concatenates user input into a raw SQL query:

```
const cds = require('@sap/cds');

class ProcessorService extends cds.ApplicationService {
  init() {
    // ✅ Expanded to handle CLOSE action (if implemented as a custom action)
    this.before(['UPDATE', 'DELETE'], 'Incidents', req => this.onModify(req));

    // ✅ Retain horizontal ESC fixes (auto-assignment, urgency handling)
    this.before("CREATE", "Incidents", req => this.onBeforeCreate(req));

    // ✅ UPDATED: Vulnerable endpoint for SQL Injection demonstration
    this.on('fetchIncident', req => this.fetchIncident(req));  // Added SQL Injection vulnerability

    return super.init();
  
  ... Other methodes
  
    // Vulnerable method: Constructs a raw SQL query using unsanitized user input
  async fetchIncident(req) {
    // User supplied incidentID without proper input validation
    const incidentID = req.data.incidentID;
    // ❌ VULNERABILITY: Directly incorporating user input into the SQL query
    const query = `SELECT * FROM "Incidents" WHERE "ID" = '${incidentID}'`;

    // ❌ CRITICAL: This query is vulnerable to SQL Injection if a malicious user 
    // injects SQL code via the incidentID field.
    let result;
    try {
      result = await cds.run(query);
    } catch (error) {
      return req.error(error);
    }
    return result;
  }

... Other methodes
```
**Why this is vulnerable:**
❌ **No Input Validation:** The user-supplied incidentID is concatenated directly into the SQL query without validation, making it possible for an attacker to inject malicious SQL code.
❌ **Lack of Parameterized Queries:** The raw SQL query does not use parameter binding or prepared statements, leaving the query structure exposed to manipulation.





    
  }
