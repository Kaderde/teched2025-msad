# Exercise 2 - Security Logging and Monitoring Failures

## 📖 Explanation :
Security Logging and Monitoring Failures is a critical web application security risk, according to the [OWASP Top 10 2021 list (A09)](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/). It occurs when an application fails to properly log security events, monitor for suspicious activities, or detect unauthorized access attempts. Without adequate logging and monitoring, organizations cannot detect breaches, investigate incidents, or maintain compliance with regulatory requirements. This can manifest in several ways:

- Missing Audit Logging.
- Inadequate Log Detail.
- Delayed Detection and Alerting.
- Insufficient Log Retention and Analysis.

## CAP Security Concept: 
  CAP provides a comprehensive audit logging framework:

- **Personal Data Protection:** Automatic audit logging for GDPR compliance using @PersonalData annotations
- **Automated Audit Events:** Built-in logging for critical operations (SensitiveDataRead, PersonalDataModified, SecurityEvent)
- **Enterprise Integration:** SAP BTP Audit Log Service with tamper-proof storage and regulatory compliance
- **Custom Security Logging:** Programmatic audit event generation via @cap-js/audit-logging.

## [Exercise 2.1 - Audit Logging for Sensitive Data Access ](./ex2.1/README.md)
## [Exercise 2.2 - Security Event Monitoring in SAP BTP Production Environment](./ex2.2/README.md)
