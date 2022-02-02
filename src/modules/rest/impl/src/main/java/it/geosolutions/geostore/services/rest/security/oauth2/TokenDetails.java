package it.geosolutions.geostore.services.rest.security.oauth2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.Serializable;

public class TokenDetails implements Serializable {

    private String idToken;
    private OAuth2AccessToken accessToken;

    public TokenDetails(OAuth2AccessToken accessToken, String idToken){
        this.idToken= idToken;
        this.accessToken=accessToken;
    }

    public <T> T getClaim(String claimName, Class<T> binding){
        DecodedJWT jwtToken=JWT.decode(idToken);
        Claim claim=jwtToken.getClaim(claimName);
        T result=null;
        if (claim!=null)
            result=claim.as(binding);
        return result;
    }

    public String getIdToken() {
        return idToken;
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
    }
}
