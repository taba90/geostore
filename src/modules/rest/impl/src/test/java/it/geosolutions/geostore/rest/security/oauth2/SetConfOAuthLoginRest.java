package it.geosolutions.geostore.rest.security.oauth2;

import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.IdPLoginRestImpl;

/**
 * Test class for the LoginRest endpoint. Allows the setting of an OAuth2Configuration object.
 */
public class SetConfOAuthLoginRest extends IdPLoginRestImpl {

    private OAuth2Configuration configuration;


    public void setConfiguration(OAuth2Configuration configuration) {
        this.configuration = configuration;
    }
}
