package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.Map;

/**
 * GeoStore specific AuthenticationConverter.
 */
public class GeoStoreAuthenticationConverter extends DefaultUserAuthenticationConverter {
    private Object usernameKey = USERNAME;

    /**
     * Default Constructor.
     */
    public GeoStoreAuthenticationConverter() {
        super();
    }

    /**
     * Default Constructor.
     */
    public GeoStoreAuthenticationConverter(final String username_key) {
        super();

        usernameKey = username_key;
    }

    @Override
    public Authentication extractAuthentication(Map<String, ?> map) {
        if (map.containsKey(usernameKey)) {
            return new UsernamePasswordAuthenticationToken(map.get(usernameKey), "N/A", null);
        }
        return null;
    }
}
