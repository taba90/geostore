package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuthGeoStoreSecurityConfiguration;
import it.geosolutions.geostore.services.rest.security.oauth2.GeoStoreOAuthRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration.CONFIG_NAME_SUFFIX;

/**
 * Configuration class for OAuth2 Google client.
 */
@Configuration
@EnableOAuth2Client
public class OAuthGoogleSecurityConfiguration extends OAuthGeoStoreSecurityConfiguration {

    static final String CONF_BEAN_NAME = "google" + CONFIG_NAME_SUFFIX;

    @Override
    public OAuth2ProtectedResourceDetails resourceDetails() {
        AuthorizationCodeResourceDetails details =
                (AuthorizationCodeResourceDetails) super.resourceDetails();
        details.setTokenName("authorization_code");
        return details;
    }

    @Bean(value = CONF_BEAN_NAME)
    public OAuth2Configuration configuration() {
        return new OAuth2Configuration();
    }

    /**
     * Must have "session" scope
     */
    @Override
    @Bean(value = "googleOpenIdRestTemplate")
    @Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
    public GeoStoreOAuthRestTemplate getConfiguredRestTemplate() {
        return super.getConfiguredRestTemplate();
    }

}
