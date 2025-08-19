# Exercise 1.2 - Vertical Privilege Escalation

## 📖  1. Overview :

Vertical Privilege Escalation occurs when a user gains access to higher-privileged functions they shouldn't have. In our Incident Management system, this means a support user could close high-urgency incidents, violating the business rule:

"Only users with the admin role can close high-urgency incidents."

### Why This Matters

* Business Impact: Unauthorized closures could lead to critical incidents being ignored or improperly resolved.
* Compliance Risk: Violates the OWASP Top 10 A01 and the principle of least privilege, a fundamental security concept
* Security Risk: Support users could maliciously or accidentally close high-urgency incidents without proper authorization.
  
In this lab, we'll focus on instance-based authorization to enforce that **"Only admin users have the authority to close high-urgency incidents."**

## 🚨 2. Vulnerable Code :

**File**: `srv/services.cds`
```cds
using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService {
  @restrict: [
    { grant: ['READ', 'CREATE'], to: 'support' },  // ✅ Support can view all incidents
    { grant: ['UPDATE', 'DELETE'],  // 
      to: 'support',
      where: 'assignedTo is null or assignedTo = $user'  // ✅ Horizontal control (correct)
    }
  ]
  entity Incidents as projection on my.Incidents;
}

annotate ProcessorService with @(requires: 'support');  // ❌ Only support role required

```
**File**: `srv/services.js`
```
const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  init() {
    this.before("UPDATE", "Incidents", (req) => this.onUpdate(req));
    this.before("CREATE", "Incidents", (req) => this.changeUrgencyDueToSubject(req.data));
    this.on("CREATE", "Incidents", (req) => this.handleIncidentCreation(req));
    return super.init();
  }


  // ❌ VULNERABILITY: No check for high-urgency incidents when status is changed to 'closed'
  async onUpdate(req) {
    // The current implementation doesn't validate if the incident has high urgency
    // when a support user tries to close it
    
    // Example validation that doesn't check urgency when closing
    const { status_code } = await SELECT.one(req.subject, i => i.status_code).where({ID: req.data.ID})
    if (status_code === 'C')
      return req.reject(`Can't modify a closed incident`)
  }

  // Other methods...
}

...

```

**Why This is Vulnerable:**

✅ What Works:
  * @restrict annotation prevents support users from modifying incidents not assigned to them (horizontal escalation privilege). it'spowerful for row-level filtering (which records you can access) but has limitations:
    1. It filters based on existing data in the database
    2. It cannot evaluate the changes being made in an update operation.
    3. It cannot compare "old value vs. new value" to enforce transition rules.

❌ What’s Missing:

  * No check for incident urgency when a support user tries to close an incident.
  * No validation prevents them from changing the status to "Closed" for high-urgency incidents.
  * Admin privileges are not automatically enforced at both service (ProcessorService) and CRUD operation level.
    
## 💥 3. Exploitation: (TBD with screenshots)

### Step 1: Login as Alice (Support User) :
- Access SAP Build Work Zone.
- Login with alice.support@company.com. This user is set up from the from the previous exercise.
- Navigate to Incident Management application.

### Step 2: Exploit the Vulnerability
- Find a high-urgency incident assigned to Alice (e.g., "Strange noise when switching off Inverter").
- Click "Edit" → Change Status to "Closed".
- Add a conversation message: "Closing this high-urgency incident as support user"
- Click "Save"

### Step 4: Verify Exploitation Success
- ✅ The system allows Alice to a high-urgency incident.
- ✅ Changes are saved successfully.
- ✅ Root Cause: No vertical privilege check to enforce the "admin-only" rule for closing high-urgency incidents.

### Step 5: Login as Admin User
- Access SAP Build Work Zone
- Login with admin credentials (e.g., admin.user@company.com)
- Navigate to Incident Management application
- UI Vulnerability: No 403 Forbidden error appears despite the admin user lacking proper authorization to access ProcessorService.
- Instead of seeing an access denied message, the admin user sees a loading indicator on blank screen.

### 📌Critical Vulnerability Summary

* ❌ Support users can close high-urgency incidents despite business rules.
* ❌ No vertical privilege escalation guardrails in @restrict or services.js.
* ❌ CAP row-level filtering cannot evaluate dynamic status transitions.
* ❌ Admin users are excluded entirely, leading to operational deadlocks.
* ❌ Silent 403 errors for admins reduce transparency and hinder troubleshooting.

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
