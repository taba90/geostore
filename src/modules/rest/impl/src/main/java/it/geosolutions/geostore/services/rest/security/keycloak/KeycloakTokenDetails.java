package it.geosolutions.geostore.services.rest.security.keycloak;

import java.util.Calendar;
import java.util.Date;

public class KeycloakTokenDetails {

    private String accessToken;
    private String refreshToken;
    private Date expiration;

    public KeycloakTokenDetails(String accessToken, String refreshToken,int exp){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
        Date epoch=new Date(0);
        this.expiration=expirationDate(epoch,exp);
    }

    public KeycloakTokenDetails(String accessToken, String refreshToken,long expIn){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
        Date start=new Date();
        this.expiration=expirationDate(start,Long.valueOf(expIn).intValue());
    }

    private Date expirationDate(Date start, int toAdd){
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(start);
        calendar.add(Calendar.SECOND, toAdd);
        return calendar.getTime();
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
