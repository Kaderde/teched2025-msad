# Exercise 1 - Broken Access Control

## 📖 Explanation :
Broken Access Control  is the most critical web application security risk, according to the [OWASP Top 10 2021 list](https://owasp.org/Top10/). It occurs when an application fails to enforce proper authorization, allowing users to access or modify resources they are not permitted to. When access control is broken, threat actors can act outside of their intended permissions. This can manifest in several ways:

- Horizontal Privilege Escalation.
- Vertical Privilege Escalation.
- Insecure Direct Object References (IDOR).

## CAP Security Concept: CAP provides a multi-layered security approach:

1. Authentication: Verifies user identity (managed by XSUAA/IAS)
2. Authorization: Controls what authenticated users can do
    - Role-based (@requires annotations)
    - Instance-based (@restrict annotations)
    - Programmatic checks (in service handlers)

The business rules for the "Incident Management" application are as follows:
- **View:** All support users can view all incidents (for context).
- **Modify:** Support users can modify incidents that are either unassigned or assigned to them.
- **Close:** Only admin users have the authority to close high-urgency incidents.

## [Exercise 1.1 - Horizontal Privilege Escalation](./ex1.1/README.md)
## [Exercise 1.2 - Vertical Privilege Escalation](./ex1.2/README.md)
## [Exercise 1.3 - - Insecure Direct Object References (IDOR)]()



