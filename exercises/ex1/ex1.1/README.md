# Exercise 1.1 - Horizontal Privilege Escalation

## 📖  1. Overview :

Horizontal Privilege Escalation occurs when a user accesses resources belonging to another user at the same privilege level. In our Incident Management system, this means a support user could modify incidents assigned to other support users, violating critical business rules:

- Support users can only modify/delete incidents explicitly assigned to them.
- No updates or deletions allowed on closed incidents.

### Why This Matters

* **Business Impact:** Unauthorized modifications could lead to incorrect incident handling, data tampering, and workflow disruption.
* **Compliance Risk:** Violates OWASP Top 10 A01:Broken Access Control and the principle of least privilege.
* **Security Risk:** Support users could alter other agents' work, close tickets improperly, or delete evidence:

## 🚨 2. Vulnerable Code :

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
    entity Incidents as projection on my.Incidents;      // ✅ Support user can view all incidents to assist effectively. (correct) 
    @readonly
    entity Customers as projection on my.Customers;      // ✅ Read-only customers (correct)
}

annotate ProcessorService.Incidents with @odata.draft.enabled; 
annotate ProcessorService with @(requires: 'support');   // ❌   VULNERABILITY: Only basic role check - no granular access control at row level

service AdminService {
    entity Customers as projection on my.Customers;      // ✅ Admin full access (correct)
    entity Incidents as projection on my.Incidents;      // ✅ Admin full access (correct)
}
annotate AdminService with @(requires: 'admin');        
```
**Why this is vulnerable:**
- The database schema lacks an 'assignedTo' field to track incident ownership.
- The @(requires: 'support') annotation only checks if the user has the support role.
- Any support user can UPDATE/DELETE any incident, regardless of assignment.


## 💥 3. Exploitation: (TBD with screenshots)

### Step 1: User and Role configuration Incident Management:

- Create users in your custom SAP Identity Service:
     - bob.support@company.com (Support user).
     - alice.support@company.com (Support user).
     - david.admin@company.com (Admin user).

- Configure User Roles in BTP cockpit
    - Assign bob.support and alice.support to role collection 'Incident Management Support' (TBD with screenshots).
    - Assign david.admin to role collection 'Incident Management Admin' (TBD with screenshots).

### Step 2: Login as Alice (Support User) :
- Access SAP Build Work Zone.
- Login with alice.support@company.com.
- Navigate to Incident Management application.

### Step 3: Exploit Modifying an Incident
- Action:
  - View the incidents list - Alice can see all incidents.
  - Click on any non-closed incident (e.g., "No current on a sunny day").
  - Click "Edit" button - **This works because there are no ownership restrictions**.
  - Modify the incident:
      - Change title to "URGENT - Modified by Alice".
      - Change status to "In Process".
      - Add a conversation entry: "Alice was here".
  - Click "Save".
- Result:
  - ❌ The system allows Alice to modify and save ANY non-closed incident.
  - ❌ Root Cause: No 'assignedTo' field,  means no ownership tracking possible.
 
### Step 4: Attempt Updating a Closed Incident
- Action:
  - Navigate to a closed incident (e.g., one with status "C").
  - Click "Edit".
  - Try to modify the incident details (e.g., change the title or add a conversation entry).
  - Click "Save".
- Result:
❌ The system prevents the update and displays an error (e.g., "403 Forbidden - Cannot modify a closed incident").
👉 This is due to the existing check in services.js, which blocks updates on closed incidents regardless of user role. However, this does not mitigate the core Horizontal Privilege Escalation issue, as Alice can still update non-closed incidents not assigned to her.

### Step 5: Exploit Deleting an Incident
- Action:
  - Navigate to any incident (e.g., "Printer issue in Office").
  - Click "Delete" (or select the incident and click the Delete button).
  - Confirm deletion when prompted (e.g., "Are you sure you want to delete this incident?").
Result:
❌ The system allows Alice to delete the incident. This violates the business rule The system does not validate a user's role before processing a deletion request.
    
### Step 6: Test with Another User
- Action:
  - Log out as Alice and log in as bob.support@company.com (another support user).
  - Repeat the update and delete actions on any incidents.
- Result:
❌ The system allows Bob to perform the same unauthorized updates and deletions, confirming that all support users have unrestricted access to all incidents.

### 📌 Critical Vulnerability Summary

* ❌ No ownership validation: Without the 'assignedTo' field in the schema, there's no way to enforce restrictions, allowing any support user to update or delete any incident.
* ❌ Partial safeguards: While updates to closed incidents are blocked, deletions remain unrestricted, amplifying risks.
* ❌ Security risks: This enables widespread data tampering and deletion, directly aligning with OWASP Top 10 A01: Broken Access Control.

## 🛡️ 4. Remediation:
The fix requires both database schema changes and service-level security implementation.

### Step 1: Add Assignment Tracking to Database Schema

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
Copy the complete code from this link: [schema.cds](./schema.cds).

### Step 2: Update Test Data with Assignments

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
Copy the complete file from this link: [sap.capire.incidents-Incidents.csv](./sap.capire.incidents-Incidents.csv).

### Step 3: Implement Service-Level Security

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
    ]
    entity Incidents as projection on my.Incidents;    

    @readonly
    entity Customers as projection on my.Customers;        
}

    annotate ProcessorService.Incidents with @odata.draft.enabled; 
    annotate ProcessorService with @(requires: ['support']);

...

```
Copy the complete code from this link: [services.cds](./services.cds).

File: `srv/services.js`

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
Copy the complete code from this link: [services.js]([./services.js).

### Step 4: Update UI to Show Assignment
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

// ✅ ADDED: PresentationVariant to explicitly control column order and visibility in the table
    UI.PresentationVariant: {
        $Type: 'UI.PresentationVariantType',
        Visualizations: [
            {
                $Type: 'UI.Chart', // Or 'UI.Table' if your main visualization is a table
                Qualifier: 'IncidentsList', // Use the correct qualifier if different (e.g., your list report's qualifier)
                Visualization: {
                    $Type: 'UI.Table',
                    // ✅ NEW: Explicitly define the default visible columns and their order
                    ColumnOrder: [
                        { Value: title },
                        { Value: customer.name },
                        { Value: urgency.descr },
                        { Value: status.descr },
                        { Value: assignedTo } // Make sure 'assignedTo' is included here
                    ]
                }
            }
        ]
    },

  // ✅ ADDED: Add 'assignedTo' field to selection fields for filtering/sorting
  UI.SelectionFields : [
      status_code,
      urgency_code,
      assignedTo, 
  ],

...

```
Copy the complete code from this link: [annotations.cds](./annotations.cds).

**File**: app/incidents/webapp/i18n.properties

```
...

// ✅ ADDED: #XFLD: Label for assigned user field
AssignedTo=Assigned To

```
Copy the complete code from this link: [i18n.properties](./i18n.properties).

## ✅ 5. Verification:
This section outlines the steps to confirm that the remediation for the Horizontal Privilege Escalation vulnerability in the Incident Management application has been successfully implemented. The goal is to ensure that support users can only modify incidents assigned to them or unassigned incidents, and that admin users retain full access, as per the business rules.

#### Step 1: Deploy the Updated Application to Cloud Foundry

```
mbt build
cf deploy mta_archives/incident-management_1.0.0.mtar
```

### Step 2: Login as Alice (Support User)
- Access SAP Build Work Zone.
- Login with alice.support@company.com.
- Navigate to Incident Management application.

### Step 3: Verify Alice Can Modify Her Own Incident
1. In the incident list, locate an incident assigned to **Alice**  *(e.g., "Strange noise when switching off Inverter")*
2. Verify the UI shows the assignment: The **Assigned To** column should display `alice.support@company.com`.
3. Click on the incident to open its details page.
4. Click the **Edit** button.
5. Attempt to modify the incident:
   1. Change the title to **"UPDATED BY ALICE - Test"**
   2. Add a conversation entry: `"Alice updated this incident"`
   3. Click **Save**

6. ✅ **Expected Result:** The incident is now in edit mode. Alice can successfully change fields such as the title, status, or add a conversation message. This confirms that the **@restrict** rule **assignedTo = $user** evaluates to true for Alice's assigned incidents.

### Step 4: Verify Alice Cannot Modify Another User's Incident
Now, we will try to perform the original attack.
1. Return to the incident list.
2. Locate an incident that is explicitly assigned to Bob, for example, "No current on a sunny day".
3. Click on this incident to view its details.
4. Click the **Edit** button.
6. ✅ **Expected Result:** The application should prevent Alice from editing this incident. clicking Edit mode will trigger an authorization error message (e.g., "Error - Forbidden"). This confirms that the **where: 'assignedTo is null or assignedTo = $user'** clause is correctly blocking Alice's unauthorized modification attempts on incidents assigned to Bob.

> **Note:**  
> If you run into a generic **"Forbidden"** error message, you can replace it with a more descriptive message by handling the error in your `services.js` file.  
> Since the `@restrict` annotation does not support custom messages by default, you’ll need to implement your own logic to provide clearer, user-friendly feedback to the end user.

## Summary

In these exercises, you have learned how:

* To address Horizontal Privilege Escalation by implementing crucial data ownership field (assignedTo) and enforcing granular authorization rules.
* To leverage CAP's native @restrict annotation and the $user context to declaratively define and enforce security policies directly within the service definition.
* To secure the application by ensuring support users can only modify incidents assigned to them, thereby reinforcing business logic and mitigating a critical OWASP Top 10 vulnerability.

Continue to - [Exercise 1.2 - Vertical Privilege Escalation](../ex1.2/README.md)
