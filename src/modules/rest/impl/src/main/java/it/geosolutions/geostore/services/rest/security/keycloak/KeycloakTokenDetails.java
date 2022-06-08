package it.geosolutions.geostore.services.rest.security.keycloak;

import java.util.Date;

public class KeycloakTokenDetails {

    private String accessToken;
    private String refreshToken;
    private Date expiration;

    public KeycloakTokenDetails(String accessToken, String refreshToken,int exp){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
        this.expiration=new Date(exp*1000);
    }

    public KeycloakTokenDetails(String accessToken, String refreshToken,long exp){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
        this.expiration=new Date(exp*1000);
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Date getExpiration() {
        return expiration;
    }
}
