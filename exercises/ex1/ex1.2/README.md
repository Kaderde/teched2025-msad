# Exercise 1.2 - Vertical Privilege Escalation

## 📖  1. Overview :

After addressing [horizontal privilege escalation in Exercise 1.1](./ex1.1/README.md), the next step is to tackle vertical privilege escalation, which occurs when a user gains access to higher-privileged functions they shouldn't have. 
In our Incident Management system, this means a support user could perform actions that are reserved for administrators, such as closing high-urgency incidents, modifying closed incidents, or deleting incidents. 
This violates critical business rules and poses significant risks to the integrity and compliance of the system.

**Business Rules:**

* Support Users:
  - ✅ Can view and create incidents.
  - ✅ Can update or delete incidents assigned to them or unassigned incidents.
  - ❌ Cannot close high-urgency incidents.
  - ❌ Cannot modify or delete closed incidents.

* Administrators:
  - ✅ Can view, create, update, and delete all incidents.
  - ✅ Can close all incidents, including high-urgency incidents.
  - ✅ Can modify or delete closed incidents.

### Why This Matters

* **Business Impact:** Unauthorized closures could lead to critical incidents being ignored or improperly resolved.
* **Compliance Risk:** Violates the OWASP Top 10 A01 and the principle of least privilege, a fundamental security concept
* **Security Risk:** Support users could close critical incidents, modify closed ones, or delete evidence without approval.

### Objective:
The objective of this exercise is to identify and remediate vulnerabilities that allow support users to perform actions reserved for administrators. By enforcing strict access controls, we will ensure that only authorized users can perform sensitive operations, thereby reinforcing business logic and mitigating security risks.

## 🚨 2. Vulnerable Code :
This is exactly the remediated code from Exercise 1.1. It correctly prevents support users from touching other users’ incidents, but it does not yet enforce admin‑only rules (e.g. closing high‑urgency incidents, modifying closed incidents, deleting any incident).

**File**: `srv/services.cds`
```cds
using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService {
  @restrict: [
    { grant: ['READ', 'CREATE'], to: 'support' },  // ✅ Support can view all incidents
    { grant: ['UPDATE', 'DELETE'],                 // ❌ VULNERABILITY: DELETE granted to support users
      to: 'support',
      where: 'assignedTo is null or assignedTo = $user'  // ✅ Horizontal control (correct)
    }
  ]
  entity Incidents as projection on my.Incidents;
}

annotate ProcessorService with @(requires: 'support');  // ❌ Only support role required, Admins excluded

```
**File**: `srv/services.js`
```
const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  init() {
    this.before("UPDATE", "Incidents", (req) => this.onUpdate(req));
    // ❌ VULNERABILITY: No DELETE handler at all
    this.before("CREATE", "Incidents", (req) => this.changeUrgencyDueToSubject(req.data));
    this.on("CREATE", "Incidents", (req) => this.handleIncidentCreation(req));
    return super.init();
  }

  // ❌ VULNERABILITY:
  // No check for admin role and for high-urgency incidents when status is changed to 'closed'
  // No check that only admins can modify closed incidents.
  // No DELETE validation

async onUpdate(req) {
  
    // Example validation that doesn't check urgency and admin role when closing
    const { status_code } = await SELECT.one(req.subject, i => i.status_code).where({ID: req.data.ID})
    if (status_code === 'C')
      return req.reject(403, "Cannot modify a closed, incident");
  }

  // Other methods...
}

...

```

**Why This is Vulnerable:**

✅ What Works:
  * @restrict prevents support users from modifying incidents not assigned to them (horizontal escalation privilege). it'spowerful for row-level filtering (which records you can access) but has limitations:
    1. It filters based on existing data in the database
    2. It cannot evaluate the changes being made in an update operation.
    3. It cannot compare "old value vs. new value" to enforce transition rules.

❌ What’s Missing:
  * DELETE permission granted to support users in CDS.
  * No DELETE validation in JavaScript to enforce admin-only deletion.
  * No check for incident urgency when a support user tries to close an incident.
  * Prevent support users from changing the status of high-urgency incidents to "Closed" and from modifying a closed incident.
  * Admin privileges are not automatically enforced at both service (ProcessorService) and CRUD operation level.
    
## 💥 3. Exploitation: (TBD with screenshots)

### Step 1: Login as Alice (Support User) :
- Access SAP Build Work Zone.
- Login with alice.support@company.com. This user is set up from the from the previous exercise.
- Navigate to Incident Management application.

### Step 2: Exploit Closing High-Urgency Incident
- Action: 
  - Find a high-urgency incident assigned to Alice (e.g., "Strange noise when switching off Inverter").
  - Click "Edit" → Change Status to "Closed".
  - Add a conversation message: "Closing this high-urgency incident as support user"
  - Click "Save"
- Result:
  - ❌ The system allows Alice to close the incident, violating the business rule.

### Step 3: Exploit Modifying a Closed Incident
- Action:
  - Locate the closed incident Alice just closed.
  - Click Edit → Change Description to "Resolved by support team."
  - Click Save.
- Result:
  - The system accepts the modification, violating the "Closed incidents can only be modified by administrators" rule.
 
### Step 4: Exploit Deleting an Incident
- Action:
  - Navigate to an incident assigned to Alice (e.g., "Printer issue in Office").
  - Click Delete (or select incident and click Delete button).
  - Confirm deletion when prompted.
- Result: ✅ System allows Alice to delete the incident, violating the "Only administrators can delete incidents" rule.
    
### Step 4: Verify Exploitation Success
  * Observation:
    - ✅ Alice closed a high-urgency incident and modified a closed incident despite lacking admin privileges.

### Step 5: Login as Admin User

- Action:
  - Log out and log in as david.admin@company.com (admin role).
  - Navigate to the closed incident modified by Alice.
  - Attempt to edit the closed incident (e.g., add a comment).
- Result:
  - ❌ UI displays a blank loading screen (no error message).
  - ❌ Root Cause: @requires: 'support' in services.cds blocks admin access to the service.

### 📌Critical Vulnerability Summary
- ❌ Support users can close high-urgency incidents and modify closed incidents.
- ❌ Admins are excluded entirely from modifying closed incidents due to misconfigured @requires.
- ❌ No validation in services.js for:
  - Admin role when closing high-urgency incidents.
  - Admin role when modifying closed incidents.
- ❌ Silent errors for admins reduce transparency and hinder operations.

## 🛡️ 4. Remediation:
The fixes follow the principle of least privilege, ensuring support users are blocked from unauthorized actions while admins retain elevated permissions.

### Key Remediation Steps

* **Enhance Service-Level and Entity-Level Authorization:** Update services.cds to include explicit grants for admins and ensure proper role requirements.
* **Implement Custom Validation Logic:** Add checks in services.js to validate urgency and user roles during UPDATE operations, rejecting invalid closures.
* **Improve UI Error Handling:** Modify the frontend to display meaningful error messages for forbidden actions.

### Step 1: Updated Code: services.cds

Update the ProcessorService definition to explicitly grant admins full access (including closing incidents) while keeping support restrictions. This ensures admins can override rules, but we'll enforce the urgency check in the JS handler.

```
// Updated srv/services.cds

using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService {
  @restrict: [
    { grant: ['READ', 'CREATE'], to: 'support' },  // Support can view and create
    { grant: ['UPDATE', 'DELETE'], 
      to: 'support',
      where: 'assignedTo is null or assignedTo = $user'  // Horizontal control for support
    },
    { grant: '*', to: 'admin' }  // ✅ NEW: Explicit full access for admins (CREATE, READ, UPDATE, DELETE)
  ]
  entity Incidents as projection on my.Incidents;

}

annotate ProcessorService with @(requires: ['support', 'admin']);  // ✅ NEW: Allow both roles support and admin at service level.

...

```
Copy the complete code from this link: [services.cds](./services.cds).

Key Changes:

* ✅ Admin Full Access: { grant: '*', to: 'admin' } grants admins complete CRUD permissions.
* ✅ Service-Level Role Requirements: @requires: ['support', 'admin'] allows both roles to access the service.

### Step 2: Updated Code: services.js
Implement custom validation logic to enforce both business rules using role-based and state-based checks.

```

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

### ✅ 5. Verification:
This section outlines the steps to confirm that the remediation for the Horizontal Privilege Escalation vulnerability in the Incident Management application has been successfully implemented. The goal is to ensure that support users can only modify incidents assigned to them or unassigned incidents, and that admin users retain full access, as per the business rules.

### Step 1: Deploy the Updated Application to Cloud Foundry

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
6. ❌ Expected Result: The application should prevent Alice from editing this incident. clicking Edit mode will trigger an authorization error message (e.g., "Error - Forbidden"). This confirms that the **where: 'assignedTo is null or assignedTo = $user'** clause is correctly blocking Alice's unauthorized modification attempts on incidents assigned to Bob.

> **Note:**  
> If you run into a generic **"Forbidden"** error message, you can replace it with a more descriptive message by handling the error in your `services.js` file.  
> Since the `@restrict` annotation does not support custom messages by default, you’ll need to implement your own logic to provide clearer, user-friendly feedback to the end user.

## Summary

In these exercises, you have learned how:

* To address Horizontal Privilege Escalation by implementing **crucial data ownership field (assignedTo)** and enforcing granular authorization rules.
* To leverage CAP's native **@restrict annotation and the $user context** to declaratively define and enforce security policies directly within the service definition.
* To secure the application by ensuring support users can **only modify incidents assigned to them**, thereby reinforcing business logic and mitigating a critical OWASP Top 10 vulnerability.

Continue to - [Exercise 1.2 - Vertical Privilege Escalation](./ex1.2/README.md)
