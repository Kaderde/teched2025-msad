# Exercise 2 - SQL injection
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
We’ll build upon [Exercise 1.2 - Vertical Privilege Escalation](../ex1/ex1.2/README.md)  by introducing an SQL Injection vulnerability resulting from unsanitized user input.

### What We're Adding

1. **CDS Service Definition (srv/services.cds):** A new fetchCustomer function in AdminService that accepts unvalidated input
2. **Vulnerable Implementation (srv/services.js):** Raw SQL query with direct string insertion
3. **Attack Surface:** HTTP POST endpoint that any admin user can exploit

**Updated File:** srv/services.cds
Add this vulnerable fetchCustomer function to your existing AdminService definition:

```
... Other methods

annotate ProcessorService.Incidents with @odata.draft.enabled; 
annotate ProcessorService with @(requires: ['support', 'admin']);  // ✅ NEW: Allow both roles support and admin at service level.

/**
 * Service used by administrators to manage customers and incidents.
 */
service AdminService {
    entity Customers as projection on my.Customers;
    entity Incidents as projection on my.Incidents;
  
  // ✅ Add fetchCustomer to AdminService - Custom Vulnerable Operation
  // ✅ Custom Vulnerable Operation: fetchIncident
  // Exposed via HTTP POST /ProcessorService/fetchIncident with JSON body
    @tags: ['security', 'vulnerable']
    @summary: 'Returns incident data using unvalidated input (for testing only)'
    function fetchCustomer(customerID: String) returns array of Customers;

annotate AdminService with @(requires: 'admin');

```
Copy the contents of [services.cds](./services.cds) into your project’s srv/services.cds file.

**Updated File:** srv/services.js

Add The fetchCustomer function handler in services.js

```
const cds = require('@sap/cds');

... Other methods

// AdminService Implementation
class AdminService extends cds.ApplicationService {
  init() {
    // ❌ VULNERABLE: fetchCustomer (SQL Injection)
    this.on('fetchCustomer', async (req) => {
      const { customerID } = req.data;
      
      // ❌ VULNERABLE CODE: SQL query uses direct string insertion
      const query = `SELECT * FROM sap.capire.incidents.Customers WHERE ID = '${customerID}'`;
      const results = await cds.run(query);
      return results;
    });

    return super.init();
  }
}
// Export both services
module.exports = {ProcessorService, AdminService
};
```
Copy the contents of [services.js](./services.js) into your project’s srv/services.js file.


**Why this is vulnerable:**
- ❌ **No Input Validation:** The user-supplied customerID is concatenated directly into the SQL query without validation, making it possible for an attacker to inject malicious SQL code.
- ❌ **Lack of Parameterized Queries:** The raw SQL query does not use parameter binding or prepared statements, leaving the query structure exposed to manipulation.

