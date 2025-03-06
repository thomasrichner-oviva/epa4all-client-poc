package com.oviva.telematik.epa4all.client;

import com.oviva.epa.client.KonnektorService;
import de.gematik.epa.ihe.model.document.Document;
import de.gematik.epa.ihe.model.simple.AuthorInstitution;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.UUID;

public class Epa4AllClientBuilder {

  Epa4AllClientBuilder konnektorService(KonnektorService konnektorService) {

    return this;
  }

  Epa4AllClient build() {
    return null;
  }
}
