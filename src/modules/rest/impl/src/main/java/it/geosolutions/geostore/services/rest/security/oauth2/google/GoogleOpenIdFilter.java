package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.security.oauth2.DiscoveryClient;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Cache;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuthGeoStoreAuthenticationFilter;
import it.geosolutions.geostore.services.rest.security.oauth2.GeoStoreOAuthRestTemplate;

/**
 * Google OAuth2 filter implementation.
 */
public class GoogleOpenIdFilter extends OAuthGeoStoreAuthenticationFilter {


    public GoogleOpenIdFilter(GeoStoreOAuthRestTemplate oAuth2RestOperations, OAuth2Configuration configuration, OAuth2Cache cache) {
        super(new GoogleTokenServices(), oAuth2RestOperations, configuration, cache);
        if (configuration.getDiscoveryUrl() != null && !"".equals(configuration.getDiscoveryUrl()))
            new DiscoveryClient(configuration.getDiscoveryUrl()).autofill(configuration);
    }

}
