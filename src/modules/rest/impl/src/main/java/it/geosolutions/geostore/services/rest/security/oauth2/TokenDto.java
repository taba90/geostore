package it.geosolutions.geostore.services.rest.security.oauth2;

public class TokenDto {

    private String jwtToken;

    private String accessToken;

    public TokenDto(String jwtToken, String accessToken) {
        this.jwtToken = jwtToken;
        this.accessToken = accessToken;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public String getAccessToken() {
        return accessToken;
    }
}
