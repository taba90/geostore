package it.geosolutions.geostore.services.rest.security.keycloak;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration("keycloakConfig")
public class KeyCloakSecurityConfiguration {

    @Bean
    public KeyCloakConfiguration keyCloakConfiguration(){
        return new KeyCloakConfiguration();
    }

    @Bean
    public KeyCloakFilter keyCloakFilter(){
        return new KeyCloakFilter(keycloackContext());
    }

    @Bean
    public AdapterDeploymentContext keycloackContext(){
        KeycloakDeployment deployment =
                KeycloakDeploymentBuilder.build(keyCloakConfiguration().readAdapterConfig());
        return new AdapterDeploymentContext(deployment);
    }

    public KeyCloakHelper keyCloakHelper(){
        return new KeyCloakHelper(keycloackContext());
    }
}
