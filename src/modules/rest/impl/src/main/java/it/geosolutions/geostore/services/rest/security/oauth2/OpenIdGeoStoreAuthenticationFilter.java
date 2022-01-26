package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.enums.Role;
import it.geosolutions.geostore.core.security.password.SecurityUtils;
import it.geosolutions.geostore.services.UserService;
import it.geosolutions.geostore.services.exception.BadRequestServiceEx;
import it.geosolutions.geostore.services.exception.NotFoundServiceEx;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static it.geosolutions.geostore.core.security.password.SecurityUtils.getUsername;

public abstract class OpenIdGeoStoreAuthenticationFilter extends OAuth2ClientAuthenticationProcessingFilter {

    private final static Logger LOGGER = Logger.getLogger(OpenIdGeoStoreAuthenticationFilter.class);

    protected static final String ID_TOKEN_PARAM ="id_token";

    protected static final String ACCESS_TOKEN_PARAM ="access_token";

    @Autowired
    protected UserService userService;

    protected RemoteTokenServices tokenServices;

    protected OAuth2ClientAuthenticationProcessingFilter filter;

    protected OAuth2Configuration configuration;

    private AuthenticationEntryPoint authEntryPoint;

    protected PreAuthUsernameProvider preAuthUsernameProvider;



    public OpenIdGeoStoreAuthenticationFilter(RemoteTokenServices tokenServices, OpenIdRestTemplate oAuth2RestOperations, OAuth2Configuration configuration,PreAuthUsernameProvider preAuthUsernameProvider){
        super("/**");
        super.setTokenServices(tokenServices);
        this.tokenServices=tokenServices;
        super.restTemplate =oAuth2RestOperations;
        this.filter=new OAuth2ClientAuthenticationProcessingFilter("/");
        this.configuration=configuration;
        this.authEntryPoint=configuration.getAuthenticationEntryPoint();
        this.preAuthUsernameProvider =preAuthUsernameProvider;

    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        super.doFilter(req, res, chain);
        chain.doFilter(req,res);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication=null;
        PreAuthUsernameDetails details= preAuthUsernameProvider.getUsername(request,response);
        String username=details!=null?details.getUsername():null;
        boolean expired=details!=null?details.isExpired():false;
        if (username!=null && !expired) authentication=createPreAuthentication(username,request,response);
        if (authentication==null){
            String accessToken = OAuthUtils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM,request);
            if (accessToken!=null) clearState();
            authentication = performOAuthAuthentication(request, new StatusResponseWrapper(response), accessToken,expired);
        }
        return authentication;
    }


    private void clearState(){
        OAuth2ClientContext clientContext = restTemplate.getOAuth2ClientContext();
        final AccessTokenRequest accessTokenRequest =
                clientContext.getAccessTokenRequest();
        if (accessTokenRequest != null && accessTokenRequest.getStateKey() != null) {
            clientContext
                    .removePreservedState(accessTokenRequest.getStateKey());
        }

        try {
            accessTokenRequest.remove(ACCESS_TOKEN_PARAM);
        } finally {
            SecurityContextHolder.clearContext();
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                    .getRequest();
            HttpSession session=request.getSession(false);
            if (session!=null)
                session.invalidate();
            LOGGER.debug("Cleaned out Session Access Token Request!");
        }
    }


    protected Authentication performOAuthAuthentication(HttpServletRequest request, StatusResponseWrapper response, String accessToken,boolean expiredPreAuth) {

        String principal = null;
        PreAuthenticatedAuthenticationToken result = null;
        try {
            principal = getPreAuthenticatedPrincipal(request, response, accessToken,expiredPreAuth);
        } catch (IOException e1) {
            LOGGER.error(e1.getMessage(), e1);
            principal = null;
        } catch (ServletException e1) {
            LOGGER.error(e1.getMessage(), e1);
            principal = null;
        }

        LOGGER.debug(
                "preAuthenticatedPrincipal = " + principal + ", trying to authenticate");

        if (principal != null && principal.trim().length() > 0)
            result = createPreAuthentication(principal, request, response);
        return result;

    }

    protected String getPreAuthenticatedPrincipal(HttpServletRequest req, StatusResponseWrapper resp, String accessToken, boolean expiredPreAuth)
            throws IOException, ServletException {

        // Make sure the REST Resource Template has been correctly configured
        configureRestTemplate();

        if (accessToken != null) {
            restTemplate
                    .getOAuth2ClientContext()
                    .setAccessToken(new DefaultOAuth2AccessToken(accessToken));
        }

        // Setting up OAuth2 Filter services and resource template
        //setRestTemplate(restTemplate);
        //setTokenServices(tokenServices);

        // Validating the access_token
        Authentication authentication = null;
        try {
            authentication = super.attemptAuthentication(req, resp);
            if (authentication!=null && LOGGER.isDebugEnabled())
                LOGGER.debug(
                    "Authenticated OAuth request for principal "+
                    authentication.getPrincipal());
        } catch (Exception e) {
            handleOAuthException(e,req,resp,expiredPreAuth);
        }

        String username =
                (authentication != null
                        ? getUsername(authentication.getPrincipal())
                        : null);
        if (username != null && username.trim().length() == 0) username = null;
        return username;
    }

    private void handleOAuthException(Exception e, HttpServletRequest req, StatusResponseWrapper resp, boolean expiredPreAuth) throws IOException, ServletException {
        if (e instanceof UserRedirectRequiredException && expiredPreAuth) {
            handleUserRedirection(req,resp);
        } else if (e instanceof BadCredentialsException
                || e instanceof ResourceAccessException) {
            if (e.getCause() instanceof OAuth2AccessDeniedException) {
                LOGGER.warn(
                        "Error while trying to authenticate to OAuth2 Provider with the following Exception cause:",
                        e.getCause());
            } else if (e instanceof ResourceAccessException) {
                LOGGER.error(
                        "Could not Authorize OAuth2 Resource due to the following exception:",
                        e);
            } else if (e instanceof ResourceAccessException
                    || e.getCause() instanceof OAuth2AccessDeniedException) {
                LOGGER.warn(
                        "It is worth notice that if you try to validate credentials against an SSH protected Endpoint, you need either your server exposed on a secure SSL channel or OAuth2 Provider Certificate to be trusted on your JVM!");
                LOGGER.info(
                        "Please refer to the GeoServer OAuth2 Plugin Documentation in order to find the steps for importing the SSH certificates.");
            } else {
                LOGGER.error(
                        "Could not Authorize OAuth2 Resource due to the following exception:",
                        e);
            }
        }
    }

    private void handleUserRedirection(HttpServletRequest req, StatusResponseWrapper resp) throws IOException, ServletException {
        if (req.getRequestURI().endsWith(configuration.getAuthorizationUri())) {
            authEntryPoint.commence(req, resp, null);
        } else {
            if (resp.getRespStatus() != 302) {
                // AEP redirection failed
                final AccessTokenRequest accessTokenRequest =
                        restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
                if (accessTokenRequest.getPreservedState() != null
                        && accessTokenRequest.getStateKey() != null) {
                   accessTokenRequest.remove("state");
                   accessTokenRequest.remove(accessTokenRequest.getStateKey());
                   accessTokenRequest.setPreservedState(null);
                }
            }
        }
    }

    protected void configureRestTemplate() {
        AuthorizationCodeResourceDetails details =
                (AuthorizationCodeResourceDetails) restTemplate.getResource();

        details.setClientId(configuration.getClientId());
        details.setClientSecret(configuration.getClientSecret());
        this.tokenServices.setClientId(configuration.getClientId());
        this.tokenServices.setClientSecret(configuration.getClientSecret());
        details.setAccessTokenUri(configuration.getAccessTokenUri());
        details.setUserAuthorizationUri(configuration.getAuthorizationUri());
        details.setPreEstablishedRedirectUri(configuration.getRedirectUri());
        this.tokenServices.setCheckTokenEndpointUrl(configuration.getCheckTokenEndpointUrl());
        details.setScope(parseScopes(Stream.of(configuration.getScopes()).collect(Collectors.joining(","))));
    }

    protected List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = newArrayList();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    protected static class StatusResponseWrapper extends HttpServletResponseWrapper{
        private int respStatus;

        public StatusResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        public int getRespStatus() {
            return respStatus;
        }

        @Override
        public void setStatus(int sc) {
            respStatus=sc;
            super.setStatus(sc);
        }
    }

    protected PreAuthenticatedAuthenticationToken createPreAuthentication(String username, HttpServletRequest request, HttpServletResponse response){
        User user=retrieveUserWithAuthorities(username,request,response);
        SimpleGrantedAuthority authority=new SimpleGrantedAuthority("ROLE_"+user.getRole().toString());
        PreAuthenticatedAuthenticationToken authenticationToken=new PreAuthenticatedAuthenticationToken(user,null, Arrays.asList(authority));
        authenticationToken.setDetails(new WebAuthenticationDetails(request));
        return authenticationToken;
    }

    protected User retrieveUserWithAuthorities(String username, HttpServletRequest request, HttpServletResponse response){
        User user=null;
        if (username !=null){
            try {
                user=userService.get(username);
            } catch (NotFoundServiceEx notFoundServiceEx) {
                LOGGER.debug("User with username "+ username+" not found.");
            }
        }
        if (user==null && configuration.getAutoCreateUser().booleanValue()){
            try {
                user=createUser(username,null,"");
            } catch (BadRequestServiceEx | NotFoundServiceEx e) {
                LOGGER.error("Error while autocreating the user: "+username,e);
            }
        }
        return user;
    }

    protected User createUser(String userName, String credentials, Object rawUser) throws BadRequestServiceEx, NotFoundServiceEx {
        User user = new User();

        user.setName(userName);
        user.setNewPassword(credentials);
        user.setEnabled(true);

        Role role = Role.USER;
        user.setRole(role);
        user.setGroups(Collections.EMPTY_SET);
        if (userService != null) {
            userService.insert(user);
        }
        return user;
    }

    @Override
    public void afterPropertiesSet() {
        // do nothing: avoid filter instantiation failing due RestTemplate bean having creation scope=session
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Authentication success. Updating SecurityContextHolder to contain: "
                    + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);
        restTemplate.getAccessToken();
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        if (failed instanceof AccessTokenRequiredException) {
            SecurityContextHolder.clearContext();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Authentication request failed: " + failed.toString(), failed);
                LOGGER.debug("Updated SecurityContextHolder to contain null Authentication");
            }
        }
    }
}
