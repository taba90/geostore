package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.security.oauth2.DiscoveryClient;
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


    public GoogleOpenIdFilter(OpenIdRestTemplate oAuth2RestOperations, OAuth2Configuration configuration, OAuthGeoStoreSecurityConfiguration secConf) {
        super(new GoogleTokenService(), oAuth2RestOperations, configuration);
        if (configuration.getDiscoveryUrl()!=null && !"".equals(configuration.getDiscoveryUrl()))
            new DiscoveryClient(configuration.getDiscoveryUrl()).autofill(configuration);
    }


    @Override
    protected String retrieveUserFromJWT(String token) {
        Jwt decoded = JwtHelper.decode(token);
        String claims = decoded.getClaims();
        JSONObject json = (JSONObject) JSONSerializer.toJSON(claims);
        String result=null;
        if(json.has("username"))
            json.getString("username");
        else if (json.has("email"))
            result=json.getString("email");
        return result;
    }
}
