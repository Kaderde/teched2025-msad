const cds = require('@sap/cds')

class ProcessorService extends cds.ApplicationService {
  /** Registering custom event handlers */
  init() {
    this.before("UPDATE", "Incidents", (req) => this.onUpdate(req));
    this.before("CREATE", "Incidents", (req) => this.changeUrgencyDueToSubject(req.data));
    // NEW:Handle the creation of new Incidents, triggering auto-assignment by the processor.
    this.on("CREATE", "Incidents", (req) => this.handleIncidentCreation(req));

    return super.init();
  }

  changeUrgencyDueToSubject(data) {
    if (data) {
      const incidents = Array.isArray(data) ? data : [data];
      incidents.forEach((incident) => {
        if (incident.title?.toLowerCase().includes("urgent")) {
          incident.urgency = { code: "H", descr: "High" };
        }
      });
    }
  }

  /** Custom Validation */
  async onUpdate (req) {
    const { status_code } = await SELECT.one(req.subject, i => i.status_code).where({ID: req.data.ID})
    if (status_code === 'C')
      return req.reject(`Can't modify a closed incident`)
  }

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