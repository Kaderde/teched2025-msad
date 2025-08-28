# Exercise 1.3 - Insecure Direct Object References (IDOR)
Vulnerability: Unauthorized Access to Credit Card Data via IDOR

## 📖  1. Overview :

Insecure Direct Object References (IDOR) occur when an application exposes internal object references(e.g., database keys, filenames, or user IDs) without proper access controls, allowing attackers to manipulate these references to access unauthorized data. In our Incident Management system, we will demonstrate how a support user can exploit IDOR to access credit card numbers stored in the Customers entity.

**Business Rules:**

* Support Users:
  - ✅ Can view customer data.
  - ❌ Cannot access customers sensitive data (e.g., credit card numbers).
  - ⚠️ All access attempts logged to SAP Audit Log Service

* Administrators:
  - ✅ Can view all customer data.
  - ⚠️ All operations, including access to sensitive fields, are logged for audit compliance.

### Why This Matters

* **Business Impact:** Unauthorized access to sensitive data (e.g., credit card numbers) could lead to data breaches, financial fraud, and loss of customer trust.
* **Compliance Risk:** Violates [PCI-DSS requirements](https://www.pcisecuritystandards.org/standards/) for protecting payment card information and the principle of least privilege.
* **Security Risk:** Support users can manipulate customer IDs in the UI/API to access restricted data.

### Objective:

The objective of this exercise is to implement **object-level authorization**, **data masking**, and **audit logging** to ensure users only access customer data they are authorized to view. By enforcing these security controls, we will restrict data visibility appropriately and maintain comprehensive records of access, thereby protecting sensitive information and mitigating unauthorized data exposure risks.

## 🚨 2. Vulnerable Code :
we will use exactly the [remediated code from Exercise 1.1.](../ex1.1#%EF%B8%8F-4-remediation), It correctly prevents support users from touching other users’ incidents, but it does not yet enforce admin‑only rules (e.g. closing high‑urgency incidents, modifying closed incidents, deleting any incident).

**File**: `db/schema.cds`
```
entity Customers : managed { 
  key ID        : String;
  firstName     : String;
  lastName      : String;
  name          : String = firstName ||' '|| lastName;
  email         : EMailAddress;
  phone         : PhoneNumber;
  incidents     : Association to many Incidents on incidents.customer = $self;
  creditCardNo  : String(16) @assert.format: '^[1-9]\d{15}$';  // ❌ No access control or masking
  addresses     : Composition of many Addresses on addresses.customer = $self;
}

```

**File**: `srv/services.cds`
```
using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService {
  @restrict: [
    { grant: ['READ', 'CREATE'], to: 'support' },  // Support can view and create
    { grant: ['UPDATE', 'DELETE'], 
      to: 'support',
      where: 'assignedTo is null or assignedTo = $user'  // Horizontal control for support
    },
    { grant: '*', to: 'admin' }  // Admin full access
  ]
  entity Incidents as projection on my.Incidents;
  
  @readonly
  entity Customers as projection on my.Customers;  // ❌ Exposes all customers data to support users.
}

annotate ProcessorService with @(requires: ['support', 'admin']); 

service AdminService {
  entity Customers as projection on my.Customers;
  entity Incidents as projection on my.Incidents;
}
annotate AdminService with @(requires: 'admin');

```

**File**: `srv/services.js`
```
const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  init() {

    // ✅ Vertical privilege escalation fixed from Exercise 1.2
    this.before(['UPDATE', 'DELETE'], 'Incidents', this.onModify)
    
    return super.init()
  }

  async onModify(req) {
    // Fetch current incident state (status + urgency)
    const result = await SELECT.one.from(req.subject)
      .columns('status_code', 'urgency_code')
      .where({ ID: req.data.ID });

    if (!result) return req.reject(404, `Incident ${req.data.ID} not found`); 
    // Check if incident is already closed
    if (result.status_code === 'C') {
      if (!req.user.isAdmin()) {
        const action = req.event === 'UPDATE' ? 'modify' : 'delete';
        return req.reject(403, `Cannot ${action} a closed incident`);
      }
      return;
    }
    
    // Check if user is attempting to close the incident
    if (req.data.status_code === 'C') {
      if (result.urgency_code === 'H' && !req.user.isAdmin()) {
        return req.reject(403, 'Only administrators can close high-urgency incidents'); 
      }
    }
   
    // ❌ VULNERABILITY
      No Audit Trail
    // No logging of access attempts to customers & incidents data, making security monitoring impossible
    
    // ❌ VULNERABILITY 1: No Audit Logging
    // No record of who accessed which incidents, when, or what they did.
    
    // ❌ VULNERABILITY 1: No API-Level READ Validation
    // Users can directly access API endpoints to read any incident data
    
    // ❌ VULNERABILITY 2: No Comprehensive Audit Logging
    // No audit trail for API access, making IDOR attacks invisible
    
    // ❌ VULNERABILITY 3: Missing Personal Data Protection
    // No @PersonalData annotations for audit logging compliance
    
    // ❌ VULNERABILITY 4: No Direct API Access Controls
    // API endpoints accessible outside of UI context without additional validation
    
  }
}

module.exports = { ProcessorService }

```

**File**: `package.json`
```
{
  "dependencies": {
    "@sap/cds": "^7",
    "@sap/cds-hana": "^2"
    // ❌ MISSING: "@cap-js/audit-logging"- Required for IDOR detection
  }
}

```

**File**: `mta.yaml`
```
modules:
  - name: incident-management-srv
    requires:
   //   ❌ MISSING: audit-log

resources:
  // ❌ MISSING: audit-log
  # Add this resource
  
```

**Why This is Vulnerable:**

- ❌ **No object-level validation:** A support user can manipulate customers IDs in the API to access other customer's data, including credit card numbers.- 
- ❌ **No data classification:** Credit card numbers are not annotated as sensitive, so audit logging isn't triggered.
- ❌ **No data masking:** Credit card numbers are displayed in full to all users.
- ❌ **No Audit Trail:**  No logging of access attempts to customers & incidents data, making security monitoring impossible.
- ❌ **No audit logging:** No record of who accessed which customers, when, or what they did.
- ❌ **Compliance Gap:** Lacks detailed audit records required by regulations like GDPR, SOX, and industry standards.

## 💥 3. Exploitation: (TBD with screenshots)
In this lab, an IDOR vulnerability is exploited via API calls in a local development environment (SAP Business Application Studio with cds watch). Unlike production, key security measures such as real authentication flows, OAuth2 tokens, and data isolation are inactive, allowing ethical hackers to safely simulate attacks, validate vulnerabilities without risking live systems, and rapidly iterate fixes before deploying to production.

### Step 1: Start Local Development Server

Action :
```
user: incident-management $ cds watch 

```
Results :

```
[cds] - connect using bindings from: { registry: '~/.cds-services.json' }
[cds] - connect to db > sqlite { url: ':memory:' }
  > init from db/data/sap.capire.incidents-Urgency.texts.csv 
  > init from db/data/sap.capire.incidents-Urgency.csv 
  > init from db/data/sap.capire.incidents-Status.texts.csv 
  > init from db/data/sap.capire.incidents-Status.csv 
  > init from db/data/sap.capire.incidents-Incidents.csv 
  > init from db/data/sap.capire.incidents-Incidents.conversation.csv 
  > init from db/data/sap.capire.incidents-Customers.csv 
  > init from db/data/sap.capire.incidents-Addresses.csv 
/> successfully deployed to in-memory database. 

[cds] - using auth strategy {
  kind: 'mocked',
  impl: 'node_modules/@sap/cds/lib/srv/middlewares/auth/basic-auth'
} 

[cds] - serving ProcessorService { impl: 'srv/services.js', path: '/odata/v4/processor' }
[cds] - serving AdminService { impl: 'srv/services.js', path: '/odata/v4/admin' }

[cds] - server listening on { url: 'http://localhost:4004' }
[cds] - server launched in: 673.811ms
```

### Step 2: List All Customers
- Action: 
  - Click on 'http://localhost:4004' to connect to your locally running CAP server.
  - Click on Customers under the Service Endpoints: /odata/v4/processor/$metadata section.
- Result:

```
{
  "@odata.context": "$metadata#Customers",
  "value": [
    {
      "createdAt": "2025-08-27T09:06:00.013Z",
      "createdBy": "anonymous",
      "modifiedAt": "2025-08-27T09:06:00.013Z",
      "modifiedBy": "anonymous",
      "ID": "1004100",
      "firstName": "Sunny",
      "lastName": "Sunshine",
      "name": "Sunny Sunshine",
      "email": "sunny.sunshine@demo.com",
      "phone": "+49-555-789",
      "creditCardNo": "3400000000000094"
    },
... Other customers' records.
  ]
}
```
- ❌ No audit record is produced in local log files or the console output of the CAP runtime for any audit entries.
- ❌ Sensitive data (e.g., credit card numbers) is not masked or protected in output.

## 🛡️ 4. Remediation:
To address the identified IDOR vulnerabilities and data privacy risks, this section implements SAP CAP's built-in security controls through:
  1. **Personal Data Annotation** - Explicitly tags sensitive fields for GDPR compliance
  2. **Automated Audit Logging** - Tracks all access to protected data with @cap-js/audit-logging
  3. **Fine-Grained Access Control** - Restricts customer data visibility by user role.

### Step 1: Add Audit Logging Dependency

- Action :
  - Add the @cap-js/audit-logging plugin to your project
  ```
  npm add @cap-js/audit-logging
  ```
Result:
  - get automatic audit logging, for personal data.
  - CRUD operation logging.
  - GDPR-compliant audit trails.

### Step 2: Annotate Personal Data

- Action : Annotate the domain model in a separate file srv/data-privacy.cds with the following content:
  
```
using { sap.capire.incidents as my } from './services';

// Annotating the my.Customers entity with @PersonalData to enable data privacy

annotate my.Customers with @PersonalData: {
  // Setting the EntitySemantics to 'DataSubject', which means it represents an individual or a group subject to data privacy regulations.
  // The DataSubjectRole is set to 'Customer'  for this specific entity.

  EntitySemantics: 'DataSubject',
  DataSubjectRole: 'Customer'

  // Annotating the fields with PersonalData attributes to differentiate between different types of data:

  ID          @PersonalData.FieldSemantics: 'DataSubjectID';  // Identifier for the data subject, can also be used to generate audit logs
  firstName   @PersonalData.IsPotentiallyPersonal;            // Personal data that can potentially identify a person (firstName,lastname,email,phone)
  lastName    @PersonalData.IsPotentiallyPersonal;            
  email       @PersonalData.IsPotentiallyPersonal;            
  phone       @PersonalData.IsPotentiallyPersonal;            
  creditCardNo @PersonalData.IsPotentiallySensitive           // Sensitive personal data requiring special treatment and access restrictions
}

// Annotating the my.Addresses entity with @PersonalData to enable data privacy

annotate my.Addresses with @PersonalData: {
  
  // Setting the EntitySemantics to 'DataSubjectDetails', which means this entity holds details related to the data subject
  
  EntitySemantics: 'DataSubjectDetails'

  // Annotating the fields with PersonalData attributes to differentiate between different types of data:

  customer    @PersonalData.FieldSemantics: 'DataSubjectID';  // Identifier for the data subject, can also be used to generate audit logs
  city        @PersonalData.IsPotentiallyPersonal;            // Personal data that can potentially identify a person : customer, city,postcode,streetAdress
  postCode    @PersonalData.IsPotentiallyPersonal;            
  streetAddress @PersonalData.IsPotentiallyPersonal;          
}
```

- Result:
  - Sensitive fields like creditCardNo are marked as @PersonalData: #Sensitive for compliance.
  - Audit logs automatically include these fields in tracking, ensuring data privacy and regulatory adherence.

## ✅ 5. Verification:

This section evaluates the implementation of audit logging and data protection in the CAP application.
Key aspects include:

* Ensuring sensitive fields (e.g., creditCardNo) are properly annotated for logging.
* Confirming role-based access controls are enforced.
* Verifying that audit logs record all API interactions, such as SensitiveDataRead, PersonalDataModified, and SecurityEvent.

Testing is performed both locally in SAP Business Application Studio and in SAP BTP environments to validate that logs are correctly generated, masked, and compliant with enterprise security standards.

### Local Environment Setup

#### Step 1: Set Up Local Server
- Action:
  - Start the CDS server in watch mode from SAP Business Application Studio command line:
    ```
    cds watch
    ```
- Results:
  - Server starts on default port (4004).
  - Test files created in /test/http/ folder at the root directory.
  - The test user is set to 'alice', ensuring audit logs are tied to this user.

#### Step 2: Test Read Access to Customers
- Action:
  - Open test/http/ProcessorService.http file in Line 119 and run the GET /odata/v4/admin/Customers request (Click on Send Request).
  - Test files was created in /test/http/ folder at the root directory with the command : cds add http --filter ProcessorService.
  - The test user is set to 'alice', ensuring audit logs are tied to this user.
  
Results:
- Audit logs show SensitiveDataRead entries for creditCardNo with timestamps matching the current time.
- Each customer record generates a separate audit log entry. 
 
  
💡 Ensure the deployment includes both updated srv/services.cds and services.js logic.

### Step 2: Login as Alice (Support User)
- Action:
  - Access SAP Build Work Zone and log in with alice.support@company.com.
  - Locate a high-urgency incident assigned to Alice or unassigned.
  - Confirm the urgency is set to "High" and the status is "New" (not closed).
  - Click "Edit" and try to set the status to "Closed" (status_code = 'C').
  - Save the changes.
- Result:
  - ❌ The system blocks the action.
  - ❌ The UI displays an error: "Only administrators can close high-urgency incidents."
  - ✅ This confirms that vertical privilege escalation is prevented for high-urgency incidents.

### Step 3: Verify Alice Can Modify Non-High-Urgency Incidents
- Action:
  - Locate a medium-urgency (code: 'M') incident assigned to Alice or unassigned.
  - Click "Edit", change status to "Closed", and save.
- Result:
  - ✅ The system allows the update and closes the incident.
  - ✅ This confirms that normal workflow operations are preserved for non-critical incidents. Support users can close regular tickets — only high-urgency closures are restricted.
 
### Step 4: Login as David (Admin User)
  - Action:
    - Log in with david.admin@company.com
    - Locate a high-urgency open incident (assigned to anyone or unassigned).
    - Click "Edit", change status to "Closed", and save.
- Result:
    - ✅ The system successfully closes the high-urgency incident.
    - ✅ This confirms that only administrators can perform sensitive actions like closing high-risk incidents, as enforced by { grant: '*', to: 'admin' } and correct role-based access control.
 
### Step 5: Verify David can Modify/Delete a Closed Incident
- Action:
  - Locate the closed incident from Step 4.
  - Edit the title or delete the incident.
- Result:
- ✅ The system allows both operations.
- ✅ This confirms admins bypass restrictions applied to support users.

### 📌 Verification Summary:

The remediation successfully addresses Vertical Privilege Escalation by:

**1. Restricting Support Users:**

  - Cannot close high-urgency incidents.
  - Cannot modify/delete closed incidents.
  - Retain modify only to their own non-high-urgency incidents.

**2. Empowering Admin Users:**
  - Full access to all incidents and operations.
  - Can close high-urgency incidents and modify closed incidents.

**3. Security Mechanisms:**
  - Declarative Security: @restrict rules in services.cds enforce role-based access.
  - Imperative Security: services.js handlers (e.g., onModify) validate business rules.
  - Defense in Depth: Combined CDS annotations and JavaScript logic prevent bypasses.

## 📌 Summary:

In these exercises, you have learned how to:
  - Mitigate Vertical Privilege Escalation by explicitly defining admin-only operations in @restrict rules.
  - Leverage CAP’s Role-Based Access Control (RBAC) to separate support and admin capabilities.
  - Combine Declarative and Imperative Security for comprehensive protection:
    * CDS Annotations (@restrict) for coarse-grained access control.
    * JavaScript Handlers (e.g., onModify) for fine-grained business logic enforcement.
  - Test Security Rules by validating both allowed and denied operations for each role.
    
Continue to - [Exercise 1.3 - Insecure Direct Object References (IDOR)](./ex1.3/README.md)
