# Exercise 2.2 – Security Event Monitoring in SAP BTP Production Environment

## 1. Overview

In this exercise you will extend the local audit-logging setup from [Exercise 2.1](./ex2.1/README.md) into a production-grade SAP BTP environment. You will:

  * Deploy the Incident Management service to SAP BTP Cloud Foundry Runtime
  * Provision and bind the managed SAP Audit Log Service to your application
  * Generate audit events via secured OData calls
  * Access, filter and verify end-to-end audit trails using the SAP Audit Log Viewer

In this exercise you will deploy your Incident Management service (with audit-logging from Ex 2.1) to SAP BTP Cloud Foundry Runtime, integrate it with the managed SAP Audit Log Service, and verify production-grade audit trails via the Audit Log Viewer.

2. Prerequisites

* Completion of Exercise 2.1 (local audit‐logging)
* SAP BTP subaccount + Cloud Foundry space
* XSUAA instance (with support/admin scopes)
* mbt & Cloud Foundry CLI installed
* Postman or Insomnia for HTTP/OAuth testing
