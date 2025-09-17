/**
 * Audit‑log middleware for CAP services
 *
 * Purpose
 * -------
 * 1️⃣ Connect to the `audit-log` service once the CAP server is up.
 * 2️⃣ Record a **SecurityEvent** whenever a request is denied (HTTP 403).
 *    • Handles normal (non‑batch) requests via the Express layer.
 *    • Handles OData batch sub‑requests via the CAP service error hook.
 *
 * How it works
 * ------------
 * • On `served` → obtain a handle to the audit‑log service (`audit`).
 * • `audit_log_403(resource, ip)` creates its own transaction (so it
 *   does not interfere with the possibly already‑failed request transaction)
 *   and writes a SecurityEvent with:
 *     – user id (or “unknown”)
 *     – action description including the protected resource name
 *     – client IP address.
 * • Middleware (`bootstrap`) watches every request; when the response
 *   finishes with status 403, it calls `audit_log_403`.
 * • For OData batch calls, the `serving` hook watches service errors;
 *   if a batch sub‑request fails with 403, it extracts the original
 *   sub‑request URL and logs the same event.
 *
 * Result
 * ------
 * All unauthorized access attempts are persistently recorded in the
 * audit‑log, providing a GDPR‑compliant audit trail for security monitoring.
 */


const cds = require('@sap/cds')

let audit

cds.on('served', async () => {
  audit = await cds.connect.to('audit-log')
})

const audit_log_403 = (resource, ip) => {
  // we need to start our own tx because the default tx may be burnt
  audit.tx(async () => {
    await audit.log('SecurityEvent', {
      data: {
        user: cds.context.user?.id || 'unknown',
        action: `Attempt to access restricted resource "${resource}" with insufficient authority`
      },
      ip
    })
  })
}

// log for non-batch requests
cds.on('bootstrap', app => {
  app.use((req, res, next) => {
    req.on('close', () => {
      if (res.statusCode == 403) {
        const { originalUrl, ip } = req
        audit_log_403(originalUrl, ip)
      }
    })
    next()
  })
})

// log for batch subrequests
cds.on('serving', srv => {
  if (srv instanceof cds.ApplicationService) {
    srv.on('error', (err, req) => {
      if (err.code == 403) {
        const { originalUrl, ip } = req.http.req
        if (originalUrl.endsWith('/$batch')) audit_log_403(originalUrl.replace('/$batch', req.req.url), ip)
      }
    })
  }
})


module.exports = cds.server
