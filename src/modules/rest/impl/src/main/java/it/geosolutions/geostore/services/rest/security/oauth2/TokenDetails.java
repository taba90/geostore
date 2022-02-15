package it.geosolutions.geostore.services.rest.security.oauth2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.Serializable;

/**
 * Holds the token details. Instances of this class are meant to be stored into the SecurityContext along with the corresponding Authentication instance.
 */
public class TokenDetails implements Serializable {

    private String idToken;
    private OAuth2AccessToken accessToken;
    private DecodedJWT decodedJWT;
    private String provider;

    /**
     * @param accessToken the accessToken instance.
     * @param idToken     the JWT idToken
     */
    public TokenDetails(OAuth2AccessToken accessToken, String idToken,String provider) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        if (idToken != null) {
            decodedJWT = JWT.decode(idToken);
        }
        this.provider=provider;
    }

    /**
     * Get a claim by name from the idToken.
     *
     * @param claimName the name of the claim to retrieve.
     * @param binding   the Class to which convert the claim value.
     * @param <T>       the type of the claim value.
     * @return the claim value.
     */
    public <T> T getClaim(String claimName, Class<T> binding) {
        T result = null;
        if (decodedJWT != null) {
            Claim claim = decodedJWT.getClaim(claimName);
            if (claim != null)
                result = claim.as(binding);
        }
        return result;
    }

    /**
     * @return the JWT idToken.
     */
    public String getIdToken() {
        return idToken;
    }

    /**
     * @return the OAuth2AccessToken instance.
     */
    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    /**
     * Set the OAuth2AccessToken.
     *
     * @param accessToken the OAuth2AccessToken.
     */
    public void setAccessToken(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public String getProvider() {
        return provider;
    }
}
