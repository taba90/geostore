package it.geosolutions.geostore.services.rest.security.oauth2.google;

import it.geosolutions.geostore.services.rest.security.oauth2.GeoStoreTokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Map;

public class GoogleTokenService extends GeoStoreTokenService {

    public GoogleTokenService() {
            super(new GoogleAccessTokenConverter());
        }

        @Override
        protected Map<String, Object> checkToken(String accessToken) {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("token", accessToken);
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", getAuthorizationHeader(accessToken));
            String accessTokenUrl =
                    new StringBuilder(checkTokenEndpointUrl)
                            .append("?access_token=")
                            .append(accessToken)
                            .toString();
            return postForMap(accessTokenUrl, formData, headers);
        }

        @Override
        protected void transformNonStandardValuesToStandardValues(Map<String, Object> map) {
            LOGGER.debug("Original map = " + map);
            map.put("client_id", map.get("issued_to")); // Google sends 'client_id' as 'issued_to'
            map.put("user_name", map.get("user_id")); // Google sends 'user_name' as 'user_id'
            LOGGER.debug("Transformed = " + map);
        }

        @Override
        protected String getAuthorizationHeader(String accessToken) {
            String creds = String.format("%s:%s", clientId, clientSecret);
            try {
                return "Basic " + new String(Base64.getEncoder().encode(creds.getBytes("UTF-8")));
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("Could not convert String");
            }
        }
}
