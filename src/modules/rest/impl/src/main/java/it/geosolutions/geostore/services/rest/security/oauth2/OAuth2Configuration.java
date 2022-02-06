package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.beans.factory.BeanNameAware;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * This class represent the geostore configuration for an OAuth2 provider.
 * An OAuth2Configuration bean should be provided for each OAuth2 provider. The bean id has to be
 * {providerName}OAuth2Config.
 */
public class OAuth2Configuration implements BeanNameAware {

    // the suffix that should be shared by all the bean of this type in their id.
    public static final String CONFIG_NAME_SUFFIX = "OAuth2Config";


    private String beanName;

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

    protected Boolean autoCreateUser = false;

    protected String idTokenUri;

    protected String discoveryUrl;

    protected String internalRedirectUri;

    protected String revokeEndpoint;

    public static final String CONFIGURATION_NAME = "CONFIGURATION_NAME";

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            String loginUri = buildLoginUri();
            if (getEnableRedirectEntryPoint()
                    || request.getRequestURI().endsWith(getAuthorizationUri())) {
                response.sendRedirect(loginUri);
            }
        };
    }

    public String buildLoginUri() {
        return buildLoginUri("online", new String[]{});
    }

    public String buildLoginUri(String accessType) {
        return buildLoginUri(accessType, new String[]{});
    }

    public String buildLoginUri(String accessType, String... additionalScopes) {
        final StringBuilder loginUri = new StringBuilder(getAuthorizationUri());
        loginUri.append("?")
                .append("response_type=code")
                .append("&")
                .append("client_id=")
                .append(getClientId())
                .append("&")
                .append("scope=")
                .append(getScopes().replace(",", "%20"));
        for (String s : additionalScopes) {
            loginUri.append("%20").append(s);
        }
        loginUri.append("&")
                .append("redirect_uri=")
                .append(getRedirectUri());
        loginUri.append("&").append("access_type=").append(accessType);
        return loginUri.toString();
    }

    public String buildRefreshTokenURI(String accessType) {
        final StringBuilder refreshUri = new StringBuilder(getAccessTokenUri());
        refreshUri.append("?")
                .append("&")
                .append("client_id=")
                .append(getClientId())
                .append("&")
                .append("scope=")
                .append(getScopes().replace(",", "%20"))
                .append("&").append("access_type=").append(accessType);
        return refreshUri.toString();
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

    public String getInternalRedirectUri() {
        return internalRedirectUri;
    }

    public void setInternalRedirectUri(String internalRedirectUri) {
        this.internalRedirectUri = internalRedirectUri;
    }

    public boolean isInvalid() {
        return clientId == null || clientSecret == null || authorizationUri == null || accessTokenUri == null;
    }

    public String getRevokeEndpoint() {
        return revokeEndpoint;
    }

    public void setRevokeEndpoint(String revokeEndpoint) {
        this.revokeEndpoint = revokeEndpoint;
    }

    @Override
    public void setBeanName(String name) {
        this.beanName = name;
    }

    public String getBeanName() {
        return beanName;
    }

    public String getProvider() {
        return beanName.replaceAll(CONFIG_NAME_SUFFIX, "");
    }
}
