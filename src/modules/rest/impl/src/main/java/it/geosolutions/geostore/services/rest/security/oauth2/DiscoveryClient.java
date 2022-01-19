package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class DiscoveryClient {
    private static final String PROVIDER_END_PATH = "/.well-known/openid-configuration";
    private static final String ISSUER_ATTR_NAME = "issuer";
    private static final String AUTHORIZATION_ENDPOINT_ATTR_NAME = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_ATTR_NAME = "token_endpoint";
    private static final String USERINFO_ENDPOINT_ATTR_NAME = "userinfo_endpoint";
    private static final String END_SESSION_ENDPONT = "end_session_endpoint";
    private static final String JWK_SET_URI_ATTR_NAME = "jwks_uri";
    private static final String SCOPES_SUPPORTED = "scopes_supported";

    private final RestTemplate restTemplate;
    private String location;

    public DiscoveryClient(String location) {
        setLocation(location);
        this.restTemplate = new RestTemplate();
    }

    public DiscoveryClient(String location, RestTemplate restTemplate) {
        setLocation(location);
        this.restTemplate = restTemplate;
    }

    private void setLocation(String location) {
        if (!location.endsWith(PROVIDER_END_PATH)) {
            location = appendPath(location, PROVIDER_END_PATH);
        }
        this.location = location;
    }
    public static String appendPath(String... pathComponents) {
        StringBuilder result = new StringBuilder(pathComponents[0]);
        for (int i = 1; i < pathComponents.length; i++) {
            String component = pathComponents[i];
            boolean endsWithSlash = result.charAt(result.length() - 1) == '/';
            boolean startsWithSlash = component.startsWith("/");
            if (endsWithSlash && startsWithSlash) {
                result.setLength(result.length() - 1);
            } else if (!endsWithSlash && !startsWithSlash) {
                result.append("/");
            }
            result.append(component);
        }

        return result.toString();
    }

    public void autofill(OAuth2Configuration conf) {
        Map response = restTemplate.getForObject(this.location, Map.class);
        Optional.ofNullable(response.get(AUTHORIZATION_ENDPOINT_ATTR_NAME))
                .ifPresent(uri -> conf.setAuthorizationUri((String) uri));
        Optional.ofNullable(response.get(TOKEN_ENDPOINT_ATTR_NAME))
                .ifPresent(uri -> conf.setAccessTokenUri((String) uri));
        Optional.ofNullable(response.get(USERINFO_ENDPOINT_ATTR_NAME))
                .ifPresent(uri -> conf.setCheckTokenEndpointUrl((String) uri));
        Optional.ofNullable(response.get(JWK_SET_URI_ATTR_NAME))
                .ifPresent(uri -> conf.setIdTokenUri((String) uri));
        Optional.ofNullable(response.get(END_SESSION_ENDPONT))
                .ifPresent(uri -> conf.setLogoutUri((String) uri));
        Optional.ofNullable(response.get(SCOPES_SUPPORTED))
                .ifPresent(
                        s -> {
                            @SuppressWarnings("unchecked")
                            List<String> scopes = (List<String>) s;
                            conf.setScopes(collectScopes(scopes));
                        });
    }

    private String collectScopes(List<String> scopes) {
        return scopes.stream().collect(Collectors.joining(" "));
    }
}
