package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.RESTSessionService;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuthSessionServiceDelegate;
import org.apache.log4j.Logger;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import static it.geosolutions.geostore.services.rest.security.oauth2.google.OAuthGoogleSecurityConfiguration.CONF_BEAN_NAME;

/**
 * Google implementation of the {@link OAuthSessionServiceDelegate}.
 */
public class GoogleSessionServiceDelegate extends OAuthSessionServiceDelegate {

    private final static Logger LOGGER = Logger.getLogger(GoogleSessionServiceDelegate.class);

    public GoogleSessionServiceDelegate(RESTSessionService restSessionService) {
        super(restSessionService, "google");
    }

    @Override
    protected void callRevokeEndpoint(String token, String url) {
        RestTemplate template = new RestTemplate();
        ResponseEntity<String> responseEntity = template.exchange(url + "?token=" + token, HttpMethod.POST, null, String.class);
        if (responseEntity.getStatusCode().value() != 200) {
            LOGGER.error("Error while revoking authorization. Error is: " + responseEntity.getBody());
        }
    }

    @Override
    protected OAuth2Configuration configuration() {
        return configuration(CONF_BEAN_NAME);
    }
}
