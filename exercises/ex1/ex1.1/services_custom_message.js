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
async onUpdate(req) {
    // Query incident with all needed fields to avoid multiple database calls
    const incident = await SELECT.one(req.subject, i => ({ 
        assignedTo: i.assignedTo,
        status_code: i.status_code 
    })).where({ ID: req.data.ID });
    
    // Check if incident exists
    if (!incident) {
        return req.reject(404, 'Incident not found');
    }
    
    // ✅ Check if incident is closed (existing logic)
    if (incident.status_code === 'C' && !req.user.is('admin')) {
        return req.reject(403, `Can't modify a closed incident`);
    }
    
    // ✅ For support users, check assignment
    if (req.user.is('support')) {
        const userEmail = req.user.id; // or req.user.attr.email depending on your setup
        
        // ✅ CUSTOM MESSAGE: Assignment check
        if (incident.assignedTo && incident.assignedTo !== userEmail) {
            return req.reject(403, 
                `🚫 Access denied. This incident is assigned to ${incident.assignedTo}. ` +
                `You can only modify incidents assigned to you or unassigned incidents.`
            );
        }
    }
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