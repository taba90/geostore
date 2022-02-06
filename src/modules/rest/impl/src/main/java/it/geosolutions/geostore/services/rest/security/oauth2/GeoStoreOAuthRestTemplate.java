package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.ID_TOKEN_PARAM;

public class GeoStoreOAuthRestTemplate extends OAuth2RestTemplate {

    private JwkTokenStore store;


    public static final String ID_TOKEN_VALUE = "OpenIdConnect-IdTokenValue";

    private String idTokenParam;


    public GeoStoreOAuthRestTemplate(
            OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context, OAuth2Configuration configuration) {
        this(resource, context, configuration, ID_TOKEN_PARAM);
    }

    public GeoStoreOAuthRestTemplate(
            OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context, OAuth2Configuration configuration, String idTokenParam) {
        super(resource, context);
        this.store = new JwkTokenStore(configuration.getIdTokenUri());
        this.idTokenParam = idTokenParam;
    }

    @Override
    public OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException {
        OAuth2AccessToken token = super.getAccessToken();
        if (token != null) extractIDToken(token);
        return token;
    }

    protected void extractIDToken(OAuth2AccessToken token) {
        Object maybeIdToken = token.getAdditionalInformation().get(idTokenParam);
        if (maybeIdToken instanceof String) {
            String idToken = (String) maybeIdToken;
            setAsRequestAttribute(ID_TOKEN_VALUE, idToken);
            // among other things, this verifies the token
            if (store != null) store.readAuthentication(idToken);
        }
    }

    private void setAsRequestAttribute(String key, String value) {
        Optional.ofNullable(RequestContextHolder.getRequestAttributes())
                .filter(ra -> ra instanceof ServletRequestAttributes)
                .map(ra -> ((ServletRequestAttributes) ra))
                .map(ServletRequestAttributes::getRequest)
                .ifPresent(r -> r.setAttribute(key, value));
    }

    public OAuth2Authentication readAuthentication(String idToken) {
        return store.readAuthentication(idToken);
    }
}
