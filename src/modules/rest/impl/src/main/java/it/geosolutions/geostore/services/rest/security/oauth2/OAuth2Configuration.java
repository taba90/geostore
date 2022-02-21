/* ====================================================================
 *
 * Copyright (C) 2022 GeoSolutions S.A.S.
 * http://www.geo-solutions.it
 *
 * GPLv3 + Classpath exception
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 *
 * ====================================================================
 *
 * This software consists of voluntary contributions made by developers
 * of GeoSolutions.  For more information on GeoSolutions, please see
 * <http://www.geo-solutions.it/>.
 *
 */

package it.geosolutions.geostore.services.rest.security.oauth2;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;

/**
 * This class represent the geostore configuration for an OAuth2 provider.
 * An OAuth2Configuration bean should be provided for each OAuth2 provider. The bean id has to be
 * {providerName}OAuth2Config.
 */
public class OAuth2Configuration implements BeanNameAware {

    // the suffix that should be shared by all the bean of this type in their id.
    public static final String CONFIG_NAME_SUFFIX = "OAuth2Config";

    private final static Logger LOGGER = Logger.getLogger(OAuth2GeoStoreAuthenticationFilter.class);



    private String beanName;

    protected String clientId;

    protected String clientSecret;

    protected String accessTokenUri;

    protected String authorizationUri;

    protected String redirectUri;

    protected String checkTokenEndpointUrl;

    protected String logoutUri;

    protected String scopes;

    protected Boolean autoCreateUser = false;

    protected String idTokenUri;

    protected String discoveryUrl;

    protected String internalRedirectUri;

    protected String revokeEndpoint;

    protected boolean enabled;

    protected boolean enableRedirectEntryPoint=false;

    public static final String CONFIGURATION_NAME = "CONFIGURATION_NAME";

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            String loginUri = buildLoginUri();
            if (request.getRequestURI().endsWith(getAuthorizationUri())) {
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
        String finalUrl= loginUri.toString();
        if(LOGGER.isDebugEnabled()) LOGGER.info("Going to request authorization to this endpoint "+finalUrl);
        return finalUrl;
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

    public Boolean getAutoCreateUser() {
        return autoCreateUser;
    }

    public void setAutoCreateUser(Boolean autoCreateUser) {
        this.autoCreateUser = autoCreateUser;
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

    protected String appendParameters(MultiValueMap<String,String> params, String url){
        UriComponentsBuilder builder=UriComponentsBuilder.fromHttpUrl(url);
        builder.queryParams(params);
        return builder.build().toUriString();
    }

    public Endpoint buildRevokeEndpoint(String token){
        Endpoint result=null;
        if (revokeEndpoint!=null){
            MultiValueMap<String,String> params=new LinkedMultiValueMap<>();
            params.put("token", Arrays.asList(token));
            result=new Endpoint(HttpMethod.POST,appendParameters(params,revokeEndpoint));
        }
        return result;
    }

    public Endpoint buildLogoutEndpoint(String token){
        Endpoint result=null;
        if (logoutUri!=null){
            MultiValueMap<String,String> params=new LinkedMultiValueMap<>();
            params.put("token", Arrays.asList(token));
            result=new Endpoint(HttpMethod.GET,appendParameters(params,logoutUri));
        }
        return result;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnableRedirectEntryPoint() {
        return enableRedirectEntryPoint;
    }

    public void setEnableRedirectEntryPoint(boolean enableRedirectEntryPoint) {
        this.enableRedirectEntryPoint = enableRedirectEntryPoint;
    }

    public static class Endpoint {

        private String url;

        private HttpMethod method;

        public Endpoint(HttpMethod method, String url){
            this.method=method;
            this.url=url;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public HttpMethod getMethod() {
            return method;
        }

        public void setMethod(HttpMethod method) {
            this.method = method;
        }
    }
}
