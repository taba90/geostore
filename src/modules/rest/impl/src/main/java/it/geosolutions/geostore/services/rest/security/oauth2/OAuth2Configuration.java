package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OAuth2Configuration {

    protected String clientId;

    protected String clientSecret;

    protected String accessTokenUri;

    protected String authorizationUri;

    protected String redirectUri;

    protected String checkTokenEndpointUrl;

    protected String logoutUri;

    protected String scopes;

    protected boolean enableRedirectEntryPoint;

    protected Boolean forceAccessTokenUriHttps;

    //protected Boolean forceUserAuthorizationUriHttps;

    protected String logoutEndpoint;

    protected Boolean autoCreateUser=false;

    protected String refreshTokenUri;

    protected String idTokenUri;

    protected String discoveryUrl;


    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return new AuthenticationEntryPoint() {
            public void commence(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    AuthenticationException authException)
                    throws IOException {
                String loginUri=buildloginUri();
                if (getEnableRedirectEntryPoint()
                        || request.getRequestURI().endsWith(getAuthorizationUri())) {
                    response.sendRedirect(loginUri);
                }
            }
        };
    }

    public String buildloginUri(){
        final StringBuilder loginUri = new StringBuilder(getAuthorizationUri());
        loginUri.append("?")
                .append("response_type=code")
                .append("&")
                .append("client_id=")
                .append(getClientId())
                .append("&")
                .append("scope=")
                .append(getScopes().replace(",", "%20"))
                .append("&")
                .append("redirect_uri=")
                .append(getRedirectUri());
        return loginUri.toString();
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String cliendId) {
        this.clientId = cliendId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAccessTokenUri() {
        return accessTokenUri;
    }

    public void setAccessTokenUri(String accessTokenUri) {
        this.accessTokenUri = accessTokenUri;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getCheckTokenEndpointUrl() {
        return checkTokenEndpointUrl;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public String getLogoutUri() {
        return logoutUri;
    }

    public void setLogoutUri(String logoutUri) {
        this.logoutUri = logoutUri;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public Boolean getEnableRedirectEntryPoint() {
        return enableRedirectEntryPoint;
    }

    public void setEnableRedirectEntryPoint(Boolean enableRedirectEntryPoint) {
        this.enableRedirectEntryPoint = enableRedirectEntryPoint;
    }

    public Boolean getForceAccessTokenUriHttps() {
        return forceAccessTokenUriHttps;
    }

    public void setForceAccessTokenUriHttps(Boolean forceAccessTokenUriHttps) {
        this.forceAccessTokenUriHttps = forceAccessTokenUriHttps;
    }

    public String getLogoutEndpoint() {
        return logoutEndpoint;
    }

    public void setLogoutEndpoint(String logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }

    public Boolean getAutoCreateUser() {
        return autoCreateUser;
    }

    public void setAutoCreateUser(Boolean autoCreateUser) {
        this.autoCreateUser = autoCreateUser;
    }

    public String getRefreshTokenUri() {
        return refreshTokenUri;
    }

    public void setRefreshTokenUri(String refreshTokenUri) {
        this.refreshTokenUri = refreshTokenUri;
    }

    public boolean isEnableRedirectEntryPoint() {
        return enableRedirectEntryPoint;
    }

    public void setEnableRedirectEntryPoint(boolean enableRedirectEntryPoint) {
        this.enableRedirectEntryPoint = enableRedirectEntryPoint;
    }

    public String getIdTokenUri() {
        return idTokenUri;
    }

    public void setIdTokenUri(String idTokenUri) {
        this.idTokenUri = idTokenUri;
    }

    public String getDiscoveryUrl() {
        return discoveryUrl;
    }

    public void setDiscoveryUrl(String discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }
}
