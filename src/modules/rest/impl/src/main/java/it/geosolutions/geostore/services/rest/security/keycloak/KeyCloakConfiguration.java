package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.services.rest.security.IdPConfiguration;
import org.apache.commons.io.IOUtils;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.adapters.config.AdapterConfig;

public class KeyCloakConfiguration extends IdPConfiguration {

    private String jsonConfig;

    public String getJsonConfig() {
        return jsonConfig;
    }

    private AdapterConfig config;

    public void setJsonConfig(String jsonConfig) {
        this.jsonConfig = jsonConfig;
    }

    public AdapterConfig readAdapterConfig(){
        if (config==null) {
            config = KeycloakDeploymentBuilder.loadAdapterConfig(
                    IOUtils.toInputStream(getJsonConfig()));
        }
        return config;
    }
}
