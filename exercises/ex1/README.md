# Exercise 1 - Broken Access Control

## 📖 1. Explanation :
Broken Access Control  is the most critical web application security risk, according to the [OWASP Top 10 2021 list](https://owasp.org/Top10/). It occurs when an application fails to enforce proper authorization, allowing users to access or modify resources they are not permitted to. When access control is broken, threat actors can act outside of their intended permissions. This can manifest in several ways:
- **Horizontal Privilege Escalation:** A threat actor gains access to another user's data or resources (e.g., User A viewing User B's private information).
- **Vertical Privilege Escalation:** A threat actor with standard user privileges gains access to administrative functions.
- **Insecure Direct Object References (IDOR):** An application uses a user-supplied identifier to access a resource directly, without checking if the user is authorized to access that specific resource.

In the "Incident Management" application used by a support team. The business rules are:
1.  Users with the `support` role can view all incidents to have context.
2.  `Support` user can only **modify** an incident that is explicitly **assigned to them**.
3.  Only users with the `admin` role can **close** incidents marked with **High** urgency.

**Objective:** identify, exploit, and fix critical privilege escalation vulnerabilities in a Node.js-based SAP CAP application.

## 🚨 2. Vulnerable Code Analysis :

**File**: `srv/services.cds`
```cds
// VULNERABLE CODE - No access restrictions
service ProcessorService { 
    entity Incidents as projection on my.Incidents;      // ✅ Can view all (correct)
    @readonly
    entity Customers as projection on my.Customers;      // ✅ Read-only customers (correct)
}

annotate ProcessorService.Incidents with @odata.draft.enabled; 
annotate ProcessorService with @(requires: 'support');   // ❌ Only role check, no assignment-based modification control

service AdminService {
    entity Customers as projection on my.Customers;      // ✅ Admin full access (correct)
    entity Incidents as projection on my.Incidents;      // ✅ Admin full access (correct)
}
annotate AdminService with @(requires: 'admin');        
```

**File**: `srv/services.js`
```
// VULNERABLE CODE - No user-based filtering
const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  init() {
    this.before("UPDATE", "Incidents", (req) => this.onUpdate(req)); // ❌ Missing: Check if incident is assigned to current user
    this.before("CREATE", "Incidents", (req) => this.changeUrgencyDueToSubject(req.data));
    return super.init();
  }

  // ❌ Only checks if incident is closed, NOT if user is assigned to it
  async onUpdate (req) {
    const { status_code } = await SELECT.one(req.subject, i => i.status_code).where({ID: req.data.ID})
    if (status_code === 'C')   // 
      return req.reject(`Can't modify a closed incident`)
    // ❌ MISSING: Check if current user is assigned to this incident
    // ❌ MISSING: Check if user has admin role for high urgency closure.
  }
}
```
**File**: db/schema.cds (Missing assignment tracking)
```
// ❌ MISSING: No assignment tracking fields
entity Incidents : cuid, managed {  
    customer     : Association to Customers;
    title        : String  @title : 'Title';
    urgency      : Association to Urgency default 'M';
    status       : Association to Status default 'N';
    // ❌ MISSING: assignedTo, assignedAt fields for tracking assignments
    conversation : Composition of many {
        key ID    : UUID;
        timestamp : type of managed:createdAt;
        author    : type of managed:createdBy;
        message   : String;
    };
}
```

The above vulnerabilities violate the principle of least privilege and can lead to data breaches and unauthorized modifications.

## 🚨 3. Exploit Horizontal Privilege Escalation Vulnerability :

### Step 1: Configure Custom Identity Service Users:
  - Create users in your custom SAP Identity Service:
     - support.user1@company.com (Support role)
     - support.user2@company.com (Support role)
     - manager.user@company.com (Admin role)
  - Assign support.user1@company.com and support.user2@company.com to role collection 'Incident Management Support'
  - Assign manager.user@company.com to role collection 'Incident Management Admin'
  
### Step 2: Demonstrate Privilege Escalation Vulnerability :
We will test with two support users to show that while they should be able to see all incidents, they should not be able to modify incidents they don't own.

**A. Test with the first user:** support.user1@company.com
 - **Login** as support.user1@company.com through SAP Build Work Zone launchpad. 
 - **Access the Incident Management application** through Work Zone launchpad
 - **Observe:** User can see ALL incidents (✅ this is correct per business rules)
 - **Exploit:** User can modify any incidents. ❌ (This is the vulnerability)
   
**B. Test with the first user:** support.user1@company.com
- Log out and then log back in as support.user2@company.com.
- Navigate to the Incident Management application again.
- Verify that this user can also modify any incident, confirming the vulnerability is not isolated to a single user.

##  ✅ 4. Fix Implementation

File: db/schema.cds (Add missing field : assignedTo)

```
using { cuid, managed, sap.common.CodeList } from '@sap/cds/common';
namespace sap.capire.incidents; 
/**
* Incidents created by Customers - SECURED
*/
entity Incidents : cuid, managed {  
    customer     : Association to Customers;
    title        : String  @title : 'Title';
    urgency      : Association to Urgency default 'M';
    status       : Association to Status default 'N';
    
    // ✅ ADD: User assignment field
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
**File**: `db/data/sap.capire.incidents-Incidents.csv`
 *   Add the `assignedTo` column and assign incidents to our test users.
 *   **Note:** Use the actual user IDs from your IdP. For this lab, we'll use their email addresses as a stand-in.
```csv
// MODIFIED FILE: db/data/sap.capire.incidents-Incidents.csv
ID,customer_ID,title,urgency_code,status_code,assignedTo
3b23bb4b-4ac7-4a24-ac02-aa10cabd842c,1004155,Inverter not functional,H,C,support.user1@company.com
3a4ede72-244a-4f5f-8efa-b17e032d01ee,1004161,No current on a sunny day,H,N,support.user1@company.com
3ccf474c-3881-44b7-99fb-59a2a4668418,1004161,Strange noise when switching off Inverter,M,N,support.user2@company.com
3583f982-d7df-4aad-ab26-301d4a157cd7,1004100,Solar panel broken,H,I,support.user2@company.com
```

:bulb: **What is a Time-based One-Time Password (TOTP)?**

A Time-based One-Time Password (TOTP) is a numerical code, which is generated with a standard algorithm that uses the current time and a key as input. It is user friendly and available offline in a generator application of the user’s choice, usually on a mobile device. A TOTP is a six-digit number that is updated every 30 seconds.


## Relevant Security Recommendations
- [SAP BTP Security Recommendations](https://help.sap.com/docs/btp/sap-btp-security-recommendations-c8a9bb59fe624f0981efa0eff2497d7d/sap-btp-security-recommendations)
- BTP-UAA-0001


## Exercise 1.1 - Setup SAP Build Apps and enter the application with your trial identity provider user


1. Open the **SAP BTP Cockpit** and navigate to your global account. You should have bookmarked the URL in the **Getting started** exercise.

2. Navigate to **Boosters**

<br><img src="/exercises/ex1/images/BoostersMenu.png" width="70%">

3. Enter SAP Build Apps in the search field. Click on **Get started with SAP Build Apps**.

<br><img src="/exercises/ex1/images/BoosterTileApps.png" width="70%">

4. An overview page provides details on the booster. Click on **Start**.

<br><img src="/exercises/ex1/images/WizardOverview.png" width="70%">

5. Now a wizard opens. On the first page, the prerequisites are checked. Click on **Next**.

<br><img src="/exercises/ex1/images/WizardStep1.png" width="70%">

6. Select the second option, **Select subaccount** and click on **Next**.

<br><img src="/exercises/ex1/images/WizardStep2.png" width="70%">

7. You can leave the default values in place. Click on **Next**.

<br><img src="/exercises/ex1/images/WizardStep3.png" width="70%">

8. Enter your email address for **Administrators** and **Developers**. Then click on **Next**.

<br><img src="/exercises/ex1/images/WizardStep4.png" width="70%">

9. Review your entries and click on **Finish**.

<br><img src="/exercises/ex1/images/WizardStep5.png" width="70%">

10. **Success!** The booster has created the SAP Build Apps setup. Click on the link to navigate to the subaccount.

<br><img src="/exercises/ex1/images/WizardStep6.png" width="70%">

11. Go to **Services --> Instances and Subscriptions** in your Subaccount - Click on the icon to open **SAP Build Apps**.

<br><img src="/exercises/ex1/images/BuildAppsLink.png" width="70%">

12. A logon page opens. Use your **Trial Account Identity Provider** to logon. There is the Default Identity Provider (SAP ID Service ) shown and your Trial Account Identity provider (SAP Cloud Identity Services).

<br><img src="/exercises/ex1/images/IdPSelection.png" width="70%">

13.  A pop-up will ask for **Email** and **Password**. Enter the email of your SAP Cloud Identity Services user and her password.

<br><img src="/exercises/ex1/images/IdPLogonPage.png" width="70%"> 

14. The authorizations should be in place as your user was assigned to the required role collections during the booster creation process. You will see the entry page of the **SAP Build App** application.

<br><img src="/exercises/ex1/images/SAPBuild.png" width="70%">

15. **Sign-out** from SAP Build Apps and close the browser window.

<br><img src="/exercises/ex1/images/SAPBuildLogout.png" width="70%">


## Exercise 1.2 - Configure Multi-Factor Authentication to access SAP Build Apps

In exercise 1.1 we enabled SAP Build Apps, and the configured users are now able to authenticate with the custom identity provider when they try to access the application. However, we want to restrict the access to the application and only allow access with a second authentication factor.

1. Logout of the SAP Build application and close the browser window if you haven't done already.

<br><img src="/exercises/ex1/images/SAPBuildLogout.png" width="70%">

2. Open the **SAP Cloud Identity Services administration console**, either from your bookmark or from the **BTP cockpit** (In the BTP Cockpit navigate to  --> **Instances and Subscriptions** --> click on the icon next to SAP Cloud Identity Services).

<br><img src="/exercises/ex1/images/IdPLink.png" width="70%">

3. In the pop-up window, sign-in with your email and password to the **SAP Cloud Identity Services administration console**.
   
<br><img src="/exercises/ex1/images/IdPLogonPageAdminConsole.png" width="70%">

4. In the **SAP Cloud Identity Services administration console**, navigate to **Applications & Resources --> Applications**.

<br><img src="/exercises/ex1/images/SCIConsoleApps.png" width="70%">

5. On the left side you see bundled and system applications. In **Bundled Applications** you find the application **SAP BTP subaccount trial**. This application represents most of the business applications that are part of the SAP BTP subaccount, including SAP Build Apps. You will find more details below in the note on XSUAA. Click on the application **SAP BTP subaccount trial** to see the configuration data of this application.

<br><img src="/exercises/ex1/images/Applications.png" width="70%">

💡  **XSUAA** is a service broker for the OAuth authorization server provided by the Cloud Foundry UAA (User Account and Authentication server). It offers authentication and authorization services for microservice-style applications. It is used by almost all applications running on SAP BTP in the Cloud Foundry environment. When we configure two-factor authentication for this application, all applications running on SAP BTP in the Cloud Foundry environment will have to provide a second factor for authentication. 
   
6. In the configuration screen of the **SAP BTP subaccount trial** application, navigate to **Authentication and Access**.
   
<br><img src="/exercises/ex1/images/AppConfig.png" width="70%">

7. Now you can see the line where **Risk-Based Authentication** can be configured. Click on the little arrow on the right.

<br><img src="/exercises/ex1/images/AppConfigRBA.png" width="70%">

8. In the **Risk-Based Authentication** frame you have the possibility to create Authentication Rules, and you can see the Default Authentication Rule, which is **Allow**.

 <br><img src="/exercises/ex1/images/AppConfigRBA_MFA.png" width="70%">

9. Change the Default Authentication Rule to **Default Action = Two-Factor Authentication** and **Two-Factor Method = TOTP**. Do not forget to **save** at the top right of the page the new configuration. Now the access to applications on your SAP BTP subaccount that use the XSUAA for authentication requires a Time-based One-time Password (TOTP) as second factor.

<br><img src="/exercises/ex1/images/AppConfigRBA_MFA_TOTP.png" width="70%">

Once the configuration is complete, the system prompts the user to select any of the available MFA options after the initial username and password are provided.

## Exercise 1.3 - Enable MFA for your user

1. Navigate to your user's profile page in **SAP Cloud Identity Services**. You can access it through the following link in the trial environment: 

**https://"trialtenant-ID".trial-accounts.ondemand.com/ui/protected/profilemanagement**

Add **ui/protected/profilemanagement** in your browser after **https://"trialtenant-ID".trial-accounts.ondemand.com/**

<br><img src="/exercises/ex1/images/Profilemanagement.png" width="70%">

Your user profile shows you the authentication methods set up for you. Here you can add or remove authentication methods. 

3. Open the Multi-Factor Authentication section. Click on **Activate TOTP Two-Factor Authentication**.

<br><img src="/exercises/ex1/images/SCIProfileActivateTOTP.png" width="70%">

4. Scan the QR code using the authenticator app (such as Google Authenticator or Microsoft Authenticator) on your device or enter the key manually. Once you have scanned or entered the key, enter the passcode generated by the authenticator app on your device below and click **Activate**.

<br><img src="/exercises/ex1/images/TOTPKey2.png" width="70%">

5. Now you have configured your device for TOTP two-factor authentication.

<br><img src="/exercises/ex1/images/TOTPKey3.png" width="70%">

6. Log out of the identity provider.

<br><img src="/exercises/ex1/images/SCILogout.png" width="70%">

7. Navigate to **SAP BTP Cockpit --> Instances and Subscriptions --> SAP Build Apps --> Go to Application**

<br><img src="/exercises/ex1/images/BuildAppsLink.png" width="70%">

8. Select your SAP Cloud Identity Services tenant to logon.

<br><img src="/exercises/ex1/images/IdPSelection.png" width="70%">

9. A pop-up will ask for **Email** and **Password**. Enter the email of your SAP Cloud Identity Services user and her password.

<br><img src="/exercises/ex1/images/IdPLogonPage.png" width="70%"> 

10. The next pop-up will ask for a **passcode**. Open the **authenticator app** you are using on our mobile device. To proceed, please enter the time-based passcode generated by your mobile device for the application. Then continue.

<br><img src="/exercises/ex1/images/TOTPLogin.png" width="70%">

11. **Success!** The SAP Build App opens.

<br><img src="/exercises/ex1/images/SAPBuild.png" width="70%">


## Summary

In this exercise you learned how to setup SAP Build and how to enable Multi-Factor Authentication (MFA) using a Time-based One-Time Password (TOTP). You will find the detailed documentation on how to set up Multi-Factor-Authentication in SAP Cloud Identity Services in the [help portal](https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/user-management-multi-factor-authentication).



Continue to - [Exercise 2 - Security Recommendations regarding user access and authentication](../ex2/README.md)
