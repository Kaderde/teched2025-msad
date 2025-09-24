# Exercise 2.2 – Security Event Monitoring in SAP BTP Production Environment

Vulnerability: A09:2021-Security Logging and Monitoring Failures

## 1. Overview

In this exercise you will extend the local audit-logging setup from [Exercise 2.1](../ex2.1/README.md) into a production-grade SAP BTP environment. You will:

  * Deploy the Incident Management service to SAP BTP Cloud Foundry Runtime.
  * Bind the managed SAP Audit Log Service to your application.
  * Generate audit events via secured OData calls.
  * Access, filter and verify end-to-end audit trails using the SAP Audit Log Viewer.

## 2. Prerequisites

* Completion of [Exercise 2.1](../ex2.1/README.md) (local audit‐logging)
* SAP BTP subaccount + Cloud Foundry space
* XSUAA instance (with support/admin scopes)
* mbt & Cloud Foundry CLI installed
* Postman or Insomnia for HTTP/OAuth testing
* SAP Work Zone launchpad configured in your BTP subaccount
* Subscribe to the SAP Audit Log Viewer service




  
