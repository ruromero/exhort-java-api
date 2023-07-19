package com.redhat.crda.representation;

import com.redhat.crda.sbom.CycloneDxSBOMGenerator;
import com.redhat.crda.sbom.SBOMGeneratorFactory;

import java.util.Map;

public class InputRepresentation {

  private Representation format;
  private CycloneDxSBOMGenerator cycloneDxSBOMGenerator;
  private String ecosystem;

  public InputRepresentation(String ecosystem) {
    this.format = Representation.SBOM;
    this.ecosystem = ecosystem;
  }

  public InputRepresentation()
  {

  }

  public RepresentationResponse sendInputForProcessing(Map<String,Object> data)
  {
    this.cycloneDxSBOMGenerator = SBOMGeneratorFactory.getSbomGenerator(this.ecosystem);
    RepresentationResponse response = new RepresentationResponse();
    response.setActualContent(cycloneDxSBOMGenerator.generateSBOM(data));
    response.setContentType("application/json");
    response.setRepresentation(Representation.SBOM);
    return response;
  }


}
