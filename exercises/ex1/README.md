# Exercise 1 - Broken Access Control

## 📖 Explanation :
Broken Access Control  is the most critical web application security risk, according to the [OWASP Top 10 2021 list](https://owasp.org/Top10/). It occurs when an application fails to enforce proper authorization, allowing users to access or modify resources they are not permitted to. When access control is broken, threat actors can act outside of their intended permissions. This can manifest in several ways:

- Horizontal Privilege Escalation.
- Vertical Privilege Escalation.
- Insecure Direct Object References (IDOR).

The business rules for the "Incident Management" application are as follows:
- **View:** All support users can view all incidents (for context).
- **Modify:** Support users can modify incidents that are either unassigned or assigned to them.
- **Close:** Only admin users have the authority to close high-urgency incidents.

### Exercise 1.1 - Horizontal Privilege Escalation

#### 📖  1. Overview :

Occurs when a user gains access to resources belonging to another user at the same privilege level. In our incident management system, this means a support user could potentially modify incidents assigned to other support users, violating the business rule that support users can only modify incidents explicitly assigned to them.

#### 🚨 2. Vulnerable Code :

**File**: `db/schema.cds`
```cds
// VULNERABLE CODE - Missing assignedTo field
using { cuid, managed, sap.common.CodeList } from '@sap/cds/common';
namespace sap.capire.incidents; 

/**
* Incidents created by Customers.
*/
entity Incidents : cuid, managed {  
  customer     : Association to Customers;
  title        : String  @title : 'Title';
  urgency      : Association to Urgency default 'M';
  status       : Association to Status default 'N';
  // ❌ MISSING: assignedTo field - no way to track incident ownership
  conversation : Composition of many {
    key ID    : UUID;
    timestamp : type of managed:createdAt;
    author    : type of managed:createdBy;
    message   : String;
  };
}
```

**File**: `srv/services.cds`
```cds
// VULNERABLE CODE - No access restrictions
service ProcessorService { 
    entity Incidents as projection on my.Incidents;      // ✅ Can view all (correct)
    @readonly
    entity Customers as projection on my.Customers;      // ✅ Read-only customers (correct)
}

annotate ProcessorService.Incidents with @odata.draft.enabled; 
annotate ProcessorService with @(requires: 'support');   // ❌   VULNERABILITY: Only basic role check - no granular access control

service AdminService {
    entity Customers as projection on my.Customers;      // ✅ Admin full access (correct)
    entity Incidents as projection on my.Incidents;      // ✅ Admin full access (correct)
}
annotate AdminService with @(requires: 'admin');        
```
**Why this is vulnerable:**
- The database schema lacks an assignedTo field to track incident ownership.
- The @(requires: 'support') annotation only checks if the user has the support role.
- Any support user can UPDATE/DELETE any incident, regardless of assignment.


#### 💥 3. Exploitation: (TBD with screenshots)
At this stage, the database doesn't have an assignedTo field, so there's no concept of incident ownership. This means ANY support user can modify ANY incident, which violates our business rules.

##### Step 1: User and Role configuration Incident Management:

- Create users in your custom SAP Identity Service:
     - bob.support@company.com (Support user).
     - alice.support@company.com (Support user).
     - david.admin@company.com (Admin user).

- Configure User Roles in BTP cockpit
    - Assign bob.support and alice.support to role collection 'Incident Management Support' (TBD with screenshots).
    - Assign david.admin to role collection 'Incident Management Admin' (TBD with screenshots).

##### Step 2: Login as Alice (Support User) :
- Access SAP Build Work Zone.
- Login with alice.support@company.com.
- Navigate to Incident Management application.

##### Step 3: Exploit the Vulnerability
- View the incidents list - Alice can see all incidents.
- Click on any incident to open it (e.g., "No current on a sunny day").
- Click "Edit" button - **This works because there are no ownership restrictions**.
- Modify the incident:
    - Change title to "URGENT - Modified by Alice".
    - Change status to "In Process".
    - Add a conversation entry: "Alice was here".
- Click "Save".

##### Step 4: Verify Exploitation Success
- ✅ The system allows Alice to modify ANY incident
- ✅ Changes are saved successfully to any incident Alice chooses
- ✅ Root Cause: No assignedTo field means no ownership tracking possible

##### Step 5: Test with Another User
- Login as Bob (bob.support@company.com).
- Bob can also modify the same incident Alice just modified.
- Bob can modify ANY incident in the system.
- Conclusion: All support users have identical, unrestricted access.

##### Current Vulnerability Summary:
- Missing Data Model: No assignedTo field to track ownership.
- No Access Control: Cannot implement "assigned to me" restrictions.
- Business Rule Violation: Support users can modify incidents they shouldn't have access to.

#### 🛡️ 4. Remediation:
The fix requires both database schema changes and service-level security implementation.

#### Step 1: Add Assignment Tracking to Database Schema

**File**: `db/schema.cds`
```cds
// db/schema.cds - FIXED VERSION
using { cuid, managed, sap.common.CodeList } from '@sap/cds/common';
namespace sap.capire.incidents; 

/**
* Incidents created by Customers.
*/
entity Incidents : cuid, managed {  
  customer     : Association to Customers;
  title        : String  @title : 'Title';
  urgency      : Association to Urgency default 'M';
  status       : Association to Status default 'N';

  // ✅ NEW: ADD User assignment fields
  assignedTo   : String(255);  // Email of assigned support user

  conversation : Composition of many {
    key ID    : UUID;
    timestamp : type of managed:createdAt;
    author    : type of managed:createdBy;
    message   : String;
  };
}
...
```
Copy the complete code from this link: [schema.cds](https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/schema.cds).

#### Step 2: Update Test Data with Assignments

File: `db/data/sap.capire.incidents-Incidents.csv`
 *   Add the `assignedTo` column and assign incidents to our test users.
 *   **Note:** Use the actual user IDs from your IdP. For this lab, we'll use their email addresses as a stand-in.

```
ID,customer_ID,title,urgency_code,status_code,assignedTo,assignedAt,assignedBy
3b23bb4b-4ac7-4a24-ac02-aa10cabd842c,1004155,Inverter not functional,H,C,bob.support@company.com
3a4ede72-244a-4f5f-8efa-b17e032d01ee,1004161,No current on a sunny day,H,N,bob.support@company.com
3ccf474c-3881-44b7-99fb-59a2a4668418,1004161,Strange noise when switching off Inverter,M,N,alice.support@company.com
3583f982-d7df-4aad-ab26-301d4a157cd7,1004100,Solar panel broken,H,I,alice.support@company.com
```
Copy the complete file from this link: [sap.capire.incidents-Incidents.csv](https://raw.githubusercontent.com/Kaderde/teched2025-msad/refs/heads/main/exercises/ex1/ex1.1/sap.capire.incidents-Incidents.csv).

#### Step 3: Implement Service-Level Security

File: `srv/services.cds`

```
using { sap.capire.incidents as my } from '../db/schema';

/**
 * Service used by support personel, i.e. the incidents' 'processors'.
 */
// ✅ SECURED: ProcessorService with proper access controls

  service ProcessorService {
    
  @restrict: [ // You can use the @restrict annotation to define authorizations on a fine-grained level.
        
        { grant: ['READ', 'CREATE'], to: 'support' },          // ✅ Support users Can view and create incidents

        // ✅ THIS IS THE KEY CHANGE:
        // Support users can only UPDATE or DELETE incidents that are either
        // unassigned (assignedTo is null) or assigned to themselves.
        { 
            grant: ['UPDATE', 'DELETE'], 
            to: 'support', 
            where: 'assignedTo is null or assignedTo = $user' 
        },

        { grant: '*', to: 'admin' }                          // ✅ Admin users has full access
    ]
    entity Incidents as projection on my.Incidents;    

    @readonly
    entity Customers as projection on my.Customers;        
}

    annotate ProcessorService.Incidents with @odata.draft.enabled; 
    annotate ProcessorService with @(requires: ['support']);

...

```
Copy the complete code from this link: [services.cds](https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/services.cds).

File: `srv/services.cds`

```
const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  /** Registering custom event handlers */
  init() {
    this.before("UPDATE", "Incidents", (req) => this.onUpdate(req));
    this.before("CREATE", "Incidents", (req) => this.changeUrgencyDueToSubject(req.data));

  // ✅ NEW:Handle the creation of new Incidents, triggering auto-assignment by the processor.
    this.on("CREATE", "Incidents", (req) => this.handleIncidentCreation(req));

    return super.init();
  }

...

  // ✅ NEW: Handle incident creation with auto-assignment 
  async handleIncidentCreation(req) {
      const incident = req.data;      if (incident.status_code === 'A' && (req.user.is('support') || req.user.is('admin'))) {
          incident.assignedTo = req.user.id;
          console.log(`📝 Auto-assigned incident to ${req.user.id}`);
      }
      this.changeUrgencyDueToSubject(incident);
  }
}

module.exports = { ProcessorService }

```
Copy the complete code from this link: [services.js]([https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/services.cds](https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/services.js)).

#### Step 4: Update UI to Show Assignment
To make the new assignedTo field visible and usable in your Fiori Elements application, you need to
add the foloowing parts in the code:

**annotations.cds file:**
  - General Information: Add assignedTo field to UI.FieldGroup #GeneratedGroup
  - Selection Fields: Added assignedTo to UI.SelectionFields for filtering/sorting

**i18n.properties file:**
  - Added new property: AssignedTo=Assigned To

**File**: app/incidents/annotations.cds changes:

```
UI.FieldGroup #GeneratedGroup : {

    $Type : 'UI.FieldGroupType',
    Data : [
        {
            $Type : 'UI.DataField',
            Value : title,
        },
        {
            $Type : 'UI.DataField',
            Label : '{i18n>Customer}',
            Value : customer_ID,
        },
        // ✅ ADDED: assignedTo field to UI.FieldGroup #GeneratedGroup
        {
            $Type : 'UI.DataField',
            Label : '{i18n>AssignedTo}', // Use consistent i18n label for assigned user in general info
            Value : assignedTo,
        },
    ],
},
...
  UI.LineItem : [
      ...
      {
          $Type : 'UI.DataField',
          Value : urgency.descr,
          Label : '{i18n>Urgency}',
      },
      // ✅ ADDED: Show assigned user in the list view
      {
          $Type : 'UI.DataField',
          Value : assignedTo,
          Label : '{i18n>AssignedTo}',
      },

  ],
  // ✅ ADDED: Add 'assignedTo' field to selection fields for filtering/sorting
  UI.SelectionFields : [
      status_code,
      urgency_code,
      assignedTo, 
  ],

...

```
Copy the complete code from this link: [annotations.cds](https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/annotations.cds).

**File**: app/incidents/webapp/i18n.properties

```
...

// ✅ ADDED: #XFLD: Label for assigned user field
AssignedTo=Assigned To

```
Copy the complete code from this link: [i18n.properties](https://github.com/Kaderde/teched2025-msad/blob/main/exercises/ex1/ex1.1/i18n.properties).

#### ✅ 5. Verification:
This section outlines the steps to confirm that the remediation for the Horizontal Privilege Escalation vulnerability in the Incident Management application has been successfully implemented. The goal is to ensure that support users can only modify incidents assigned to them or unassigned incidents, and that admin users retain full access, as per the business rules.

#### Step 1: Deploy the Updated Application to Cloud Foundry

```
mbt build
cf deploy mta_archives/incident-management_1.0.0.mtar
```

#### Step 2: Login as Alice (Support User)

- Access SAP Build Work Zone.
- Login with alice.support@company.com.
- Navigate to Incident Management application.

#### Step 3: Verify Access to an Incident Assigned to Alice
- In the incident list, find an incident assigned to Alice, for example, "Strange noise when switching off Inverter".
- Click on the incident to open its details page.
- Click the "Edit" button.

✅ **Expected Result:** The application enters edit mode. Alice can successfully modify the title, status, or add a conversation entry because the incident is assigned to her (assignedTo = $user is true). This confirms that legitimate access is still working. You can cancel the edit without saving.

#### Step 4: Attempt to Exploit the Vulnerability (as Alice)
Now, we will try to perform the original attack.
- Go back to the incident list.
- Find an incident that is explicitly assigned to Bob, for example, "No current on a sunny day".
- Click on the incident to open its details page.
- Click the "Edit" button.


#### Step 5: Redeploy the Application



## Summary

In this exercise you learned how to setup SAP Build and how to enable Multi-Factor Authentication (MFA) using a Time-based One-Time Password (TOTP). You will find the detailed documentation on how to set up Multi-Factor-Authentication in SAP Cloud Identity Services in the [help portal](https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/user-management-multi-factor-authentication).



Continue to - [Exercise 2 - Security Recommendations regarding user access and authentication](../ex2/README.md)
