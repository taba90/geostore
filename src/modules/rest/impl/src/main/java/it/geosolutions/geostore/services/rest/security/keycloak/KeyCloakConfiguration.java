package it.geosolutions.geostore.services.rest.security.keycloak;

import org.apache.commons.io.IOUtils;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.adapters.config.AdapterConfig;

public class KeyCloakConfiguration {

    private String jsonConfig;

    public String getJsonConfig() {
        return jsonConfig;
    }

    public void setJsonConfig(String jsonConfig) {
        this.jsonConfig = jsonConfig;
    }

    public AdapterConfig readAdapterConfig(){
        return KeycloakDeploymentBuilder.loadAdapterConfig(
                IOUtils.toInputStream(getJsonConfig()));
    }
}
