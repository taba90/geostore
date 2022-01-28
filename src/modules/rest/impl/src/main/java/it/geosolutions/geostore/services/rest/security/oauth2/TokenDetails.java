package it.geosolutions.geostore.services.rest.security.oauth2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.Serializable;

public class TokenDetails implements Serializable {

    private DecodedJWT jwtToken;
    private OAuth2AccessToken accessToken;

    public TokenDetails(OAuth2AccessToken accessToken, String idToken){
        this.jwtToken= JWT.decode(idToken);
        this.accessToken=accessToken;
    }

    public <T> T getClaim(String claimName, Class<T> binding){
        Claim claim=jwtToken.getClaim(claimName);
        T result=null;
        if (claim!=null)
            result=claim.as(binding);
        return result;
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }
}
