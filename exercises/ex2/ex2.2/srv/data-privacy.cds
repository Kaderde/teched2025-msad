using {sap.capire.incidents as my} from './services';

annotate my.Customers with @PersonalData: {
  EntitySemantics: 'DataSubject',
  DataSubjectRole: 'Customer',
} {
  ID            @PersonalData.FieldSemantics : 'DataSubjectID';
  firstName     @PersonalData.IsPotentiallyPersonal;
  lastName      @PersonalData.IsPotentiallyPersonal;
  email         @PersonalData.IsPotentiallyPersonal;
  phone         @PersonalData.IsPotentiallyPersonal;
  creditCardNo  @PersonalData.IsPotentiallySensitive;
}

annotate my.Addresses with @PersonalData: {
  EntitySemantics: 'DataSubjectDetails'
} {
  customer      @PersonalData.FieldSemantics: 'DataSubjectID';
  city          @PersonalData.IsPotentiallyPersonal;
  postCode      @PersonalData.IsPotentiallyPersonal;
  streetAddress @PersonalData.IsPotentiallyPersonal;
}

// Annotating the my.Incidents entity with @PersonalData to enable data privacy
annotate my.Incidents with @PersonalData: {
  EntitySemantics: 'DataSubjectDetails',                         // Incidents relate to data subjects (customers)  
  ID            @PersonalData.FieldSemantics: 'DataSubjectID',   // Link to customer  
  title         @PersonalData.IsPotentiallyPersonal,             // May contain PII  
  status_code   @PersonalData.IsPotentiallyPersonal,
  urgency_code  @PersonalData.IsPotentiallyPersonal,
  assignedTo    @PersonalData.IsPotentiallyPersonal
  conversation  @PersonalData: {  
    message     @PersonalData.IsPotentiallySensitive             // Messages may include sensitive details  
  };

};

