package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.security.oauth2.DiscoveryClient;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Cache;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.OpenIdGeoStoreAuthenticationFilter;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuthGeoStoreSecurityConfiguration;
import it.geosolutions.geostore.services.rest.security.oauth2.OpenIdRestTemplate;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

public class GoogleOpenIdFilter extends OpenIdGeoStoreAuthenticationFilter {


    public GoogleOpenIdFilter(OpenIdRestTemplate oAuth2RestOperations, OAuth2Configuration configuration, OAuth2Cache cache) {
        super(new GoogleTokenService(), oAuth2RestOperations, configuration,cache);
        if (configuration.getDiscoveryUrl()!=null && !"".equals(configuration.getDiscoveryUrl()))
            new DiscoveryClient(configuration.getDiscoveryUrl()).autofill(configuration);
    }

}
