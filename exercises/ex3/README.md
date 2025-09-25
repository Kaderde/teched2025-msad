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

... Other methods

// AdminService Implementation
class AdminService extends cds.ApplicationService {
  init() {
    // ❌ VULNERABLE: fetchCustomer (SQL Injection)
    this.on('fetchCustomer', async (req) => {
      const { customerID } = req.data;
      
      // ❌ VULNERABLE CODE: Direct string interpolation in query
      const query = `SELECT * FROM sap.capire.incidents.Customers WHERE ID = '${customerID}'`;
      const results = await cds.run(query);
      return results;
    });

    return super.init();
  }
}

```
**Why this is vulnerable:**
❌ **No Input Validation:** The user-supplied customerID is concatenated directly into the SQL query without validation, making it possible for an attacker to inject malicious SQL code.
❌ **Lack of Parameterized Queries:** The raw SQL query does not use parameter binding or prepared statements, leaving the query structure exposed to manipulation.







    
  }
