package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.UserAttribute;
import it.geosolutions.geostore.core.model.UserGroup;
import it.geosolutions.geostore.core.model.enums.Role;
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
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static it.geosolutions.geostore.core.security.password.SecurityUtils.getUsername;
import static it.geosolutions.geostore.services.rest.SessionServiceDelegate.PROVIDER_KEY;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.REFRESH_TOKEN_PARAM;

public abstract class OAuthGeoStoreAuthenticationFilter extends OAuth2ClientAuthenticationProcessingFilter {

    private final static Logger LOGGER = Logger.getLogger(OAuthGeoStoreAuthenticationFilter.class);


    @Autowired
    protected UserService userService;

    protected RemoteTokenServices tokenServices;

    protected OAuth2Configuration configuration;

    private AuthenticationEntryPoint authEntryPoint;

    private OAuth2Cache cache;



    public OAuthGeoStoreAuthenticationFilter(RemoteTokenServices tokenServices, GeoStoreOAuthRestTemplate oAuth2RestOperations, OAuth2Configuration configuration, OAuth2Cache oAuth2Cache){
        super("/**");
        super.setTokenServices(tokenServices);
        this.tokenServices=tokenServices;
        super.restTemplate =oAuth2RestOperations;
        this.configuration=configuration;
        this.authEntryPoint=configuration.getAuthenticationEntryPoint();
        this.cache=oAuth2Cache;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        Authentication authentication=SecurityContextHolder.getContext().getAuthentication();
        if (!configuration.isInvalid() && authentication==null)
            super.doFilter(req, res, chain);
        else if (req instanceof HttpServletRequest)
            addRequestAttributes((HttpServletRequest)req,authentication);
        chain.doFilter(req,res);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication;
            String token = OAuthUtils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM, request);
            if (token!=null) {
                authentication = cache.get(token);
                if (authentication==null) {
                    authentication=authenticateAndUpdateCache(request,response,token,new DefaultOAuth2AccessToken(token));
                } else {
                    TokenDetails details = tokenDetails(authentication);
                    if (details!=null) {
                        OAuth2AccessToken accessToken = details.getAccessToken();
                        if (accessToken.isExpired())
                            authentication = authenticateAndUpdateCache(request, response, token, accessToken);
                    }
                }
            } else {
                clearState();
                authentication=authenticateAndUpdateCache(request,response,null,null);
            }
        return authentication;
    }

    private TokenDetails tokenDetails(Authentication authentication){
        TokenDetails tokenDetails=null;
        Object details=authentication.getDetails();
        if (details instanceof TokenDetails){
            tokenDetails=((TokenDetails)details);
        }
        return tokenDetails;
    }



    private Authentication authenticateAndUpdateCache(HttpServletRequest request, HttpServletResponse response, String token, OAuth2AccessToken accessToken){
        Authentication authentication=performOAuthAuthentication(request,response,accessToken);
        if (authentication!=null) {
            TokenDetails tokenDetails = tokenDetails(authentication);
            if (tokenDetails != null) {
                token = tokenDetails.getAccessToken().getValue();
            }
            cache.putCacheEntry(token,authentication);
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


    protected Authentication performOAuthAuthentication(HttpServletRequest request, HttpServletResponse response, OAuth2AccessToken accessToken) {

        String principal = null;
        PreAuthenticatedAuthenticationToken result = null;
        try {
            principal = getPreAuthenticatedPrincipal(request, response, accessToken);
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

    protected String getPreAuthenticatedPrincipal(HttpServletRequest req, HttpServletResponse resp, OAuth2AccessToken accessToken)
            throws IOException, ServletException {

        // Make sure the REST Resource Template has been correctly configured
        configureRestTemplate();
        if (accessToken != null) {
            restTemplate
                    .getOAuth2ClientContext()
                    .setAccessToken(accessToken);
        }

        // Setting up OAuth2 Filter services and resource template
        //setRestTemplate(restTemplate);
        //setTokenServices(tokenServices);

        // Validating the access_token
        Authentication authentication = null;
        StatusResponseWrapper respWrap=new StatusResponseWrapper(resp);
        try {
            authentication = super.attemptAuthentication(req, respWrap);
            if (authentication!=null && LOGGER.isDebugEnabled())
                LOGGER.debug(
                    "Authenticated OAuth request for principal "+
                    authentication.getPrincipal());
        } catch (Exception e) {
            handleOAuthException(e,req,respWrap);
        }

        String username =
                (authentication != null
                        ? getUsername(authentication.getPrincipal())
                        : null);
        if (username != null && username.trim().length() == 0) username = null;
        return username;
    }

    private void handleOAuthException(Exception e, HttpServletRequest req, StatusResponseWrapper resp) throws IOException, ServletException {
        if (e instanceof UserRedirectRequiredException && configuration.getEnableRedirectEntryPoint()) {
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
        String idToken=OAuthUtils.getIdToken();
        OAuth2AccessToken accessToken=restTemplate.getOAuth2ClientContext().getAccessToken();
        authenticationToken.setDetails(new TokenDetails(accessToken,idToken));
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
        UserAttribute userAttribute= new UserAttribute();
        userAttribute.setName(OAuth2Configuration.CONFIGURATION_NAME);
        userAttribute.setValue(configuration.getBeanName());
        user.setAttribute(Arrays.asList(userAttribute));
        Role role = Role.USER;
        user.setRole(role);
        Set<UserGroup> groups=new HashSet<UserGroup>();
        /*UserGroup everyoneGroup = new UserGroup();
        everyoneGroup.setEnabled(true);
        everyoneGroup.setId(-1L);
        everyoneGroup.setGroupName(GroupReservedNames.EVERYONE.groupName());
        groups.add(everyoneGroup);*/
        user.setGroups(groups);
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
        TokenDetails tokenDetails=tokenDetails(authResult);
        addRequestAttributes(request,authResult);
        request.setAttribute(PROVIDER_KEY,configuration.getProvider());
    }

    private void addRequestAttributes(HttpServletRequest request,Authentication authentication){
        TokenDetails tokenDetails=tokenDetails(authentication);
        if (tokenDetails!=null && tokenDetails.getAccessToken() !=null){
            OAuth2AccessToken accessToken=tokenDetails.getAccessToken();
            request.setAttribute(ACCESS_TOKEN_PARAM, accessToken.getValue());
            if (accessToken.getRefreshToken()!=null)
                request.setAttribute(REFRESH_TOKEN_PARAM,accessToken.getRefreshToken().getValue());
        }
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
