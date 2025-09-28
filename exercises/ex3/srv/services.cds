using { sap.capire.incidents as my } from '../db/schema';

service ProcessorService {
  @restrict: [
    { grant: ['READ', 'CREATE'], to: 'support' },
    { grant: ['UPDATE', 'DELETE'], 
      to: 'support',
      where: 'assignedTo is null or assignedTo = $user'
    },
    { grant: '*', to: 'admin' }
  ]
  entity Incidents as projection on my.Incidents;
  
  @readonly
  entity Customers as projection on my.Customers;
}

annotate ProcessorService.Incidents with @odata.draft.enabled; 
annotate ProcessorService with @(requires: ['support', 'admin']);

service AdminService {
  @restrict: { grant: '*', to: 'admin' }
  @odata
  
  entity Customers as projection on my.Customers;
  entity Incidents as projection on my.Incidents;
  
  // ✅ Add Custom Vulnerable Operation fetchCustomer to AdminService
  // ✅ Exposed via HTTP GET  {{server}}/odata/v4/admin/fetchCustomer with JSON body
    @tags: ['security', 'vulnerable']
    @summary: 'Returns incident data using unvalidated input (for testing only)'
    function fetchCustomer(customerID: String) returns array of Customers;
}

annotate AdminService with @(requires: 'admin');
