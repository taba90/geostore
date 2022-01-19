package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.services.exception.BadRequestServiceEx;
import it.geosolutions.geostore.services.exception.NotFoundServiceEx;
import it.geosolutions.geostore.services.rest.security.GeoStoreAuthenticationFilter;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.log4j.Logger;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static it.geosolutions.geostore.core.security.password.SecurityUtils.getUsername;

public abstract class OpenIdGeoStoreAuthenticationFilter extends GeoStoreAuthenticationFilter {

    private final static Logger LOGGER = Logger.getLogger(OpenIdGeoStoreAuthenticationFilter.class);

    protected static final String ID_TOKEN_PARAM ="id_token";

    protected static final String ACCESS_TOKEN_PARAM ="access_token";

    protected RemoteTokenServices tokenServices;

    protected OpenIdRestTemplate restTemplate;

    protected OAuth2ClientAuthenticationProcessingFilter filter;

    protected OAuth2Configuration configuration;
    private AuthenticationEntryPoint authEntryPoint;


    public OpenIdGeoStoreAuthenticationFilter(RemoteTokenServices tokenServices, OpenIdRestTemplate oAuth2RestOperations, OAuth2Configuration configuration){
        this.tokenServices=tokenServices;
        this.restTemplate =oAuth2RestOperations;
        this.filter=new OAuth2ClientAuthenticationProcessingFilter("/");
        this.configuration=configuration;
        this.authEntryPoint=configuration.getAuthenticationEntryPoint();
    }

    @Override
    protected void authenticate(HttpServletRequest req) {
        String token = getParameterValue(ID_TOKEN_PARAM, req);
        if (token==null)
            token = getBearerToken(req);
        Authentication authentication= authenticate(token,req,getHttpResponse());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    protected Authentication authenticate(String token,HttpServletRequest req, StatusResponseWrapper resp) {
            Authentication authentication=SecurityContextHolder.getContext().getAuthentication();
            OAuth2ClientContext clientContext = restTemplate.getOAuth2ClientContext();
            HttpServletRequest httpServletRequest = getHttpRequest();
            if (token!=null){
                authentication=authenticationByTokenId(token,req,resp);
            }
            if (authentication == null) {
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
                    authentication = null;
                    LOGGER.debug("Cleaned out Session Access Token Request!");
                }
            }

            if (authentication == null) {
                String accessToken = (String) RequestContextHolder.getRequestAttributes().getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, 1);
                authentication = performOAuthAuthentication(httpServletRequest, getHttpResponse(), accessToken);
            }
            setCookie(resp,token);
        return authentication;
    }

    protected Authentication authenticationByTokenId(String token, HttpServletRequest req, StatusResponseWrapper resp){
        Authentication authentication=null;
         if (token!=null){
             try {
                 String username =retrieveUserFromJWT(token);
                     if (username!=null && !"".equals(username))
                         authentication=createPreAuthentication(username,req,resp);
             } catch (InvalidTokenException e){
                 if (LOGGER.isDebugEnabled()){
                     LOGGER.debug("Invalid token id. Will try to authenticate user using the authorization workflow.");
                 }
             }
        }
         return authentication;
    }


    protected Authentication performOAuthAuthentication(HttpServletRequest request, StatusResponseWrapper response, String token) {

        String principal = null;
        PreAuthenticatedAuthenticationToken result = null;
        try {
            principal = getPreAuthenticatedPrincipal(request, response, token);
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

    protected String getPreAuthenticatedPrincipal(HttpServletRequest req, StatusResponseWrapper resp, String token)
            throws IOException, ServletException {

        // Make sure the REST Resource Template has been correctly configured
        configureRestTemplate();

        if (token != null) {
            restTemplate
                    .getOAuth2ClientContext()
                    .setAccessToken(new DefaultOAuth2AccessToken(token));
        }

        // Setting up OAuth2 Filter services and resource template
        filter.setRestTemplate(restTemplate);
        filter.setTokenServices(tokenServices);

        // Validating the access_token
        Authentication authentication = null;
        try {
            authentication = filter.attemptAuthentication(req, null);
            if (authentication!=null && LOGGER.isDebugEnabled())
                LOGGER.debug(
                    "Authenticated OAuth request for principal "+
                    authentication.getPrincipal());
        } catch (Exception e) {
            handleOAuthException(e,req,resp);
        }

        String username =
                (authentication != null
                        ? getUsername(authentication.getPrincipal())
                        : null);
        if (username != null && username.trim().length() == 0) username = null;
        // will see req.setAttribute(UserNameAlreadyRetrieved, Boolean.TRUE);
        // will see if (username != null) req.setAttribute(UserName, username);
        return username;
    }

    private void handleOAuthException(Exception e, HttpServletRequest req, StatusResponseWrapper resp) throws IOException, ServletException {
        if (e instanceof UserRedirectRequiredException) {
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
                        e.getCause());
            }
        }
    }

    private void handleUserRedirection(HttpServletRequest req, StatusResponseWrapper resp) throws IOException, ServletException {
        if (configuration.getEnableRedirectEntryPoint()
                || req.getRequestURI().endsWith(configuration.getAuthorizationUri())) {
            // Provider login URI
            authEntryPoint.commence(req, resp, null);
        } else {
            if (resp.getRespStatus() != 302) {
                // AEP redirection failed
                final AccessTokenRequest accessTokenRequest =
                        restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
                if (accessTokenRequest.getPreservedState() != null
                        && accessTokenRequest.getStateKey() != null) {
                   // accessTokenRequest.remove("state");
                   // accessTokenRequest.remove(accessTokenRequest.getStateKey());
                   // accessTokenRequest.setPreservedState(null);
                }
            }
        }
    }

    private HttpServletRequest getHttpRequest(){
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getRequest();
    }

    private StatusResponseWrapper getHttpResponse(){
        HttpServletResponse resp=((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getResponse();
        return new StatusResponseWrapper(resp);
    }

    protected String getParameterValue(String paramName, ServletRequest request) {
        for (Enumeration<String> iterator = request.getParameterNames();
             iterator.hasMoreElements(); ) {
            final String param = iterator.nextElement();
            if (paramName.equalsIgnoreCase(param)) {
                return request.getParameter(param);
            }
        }

        return null;
    }

    protected String getBearerToken(HttpServletRequest request) {
        Authentication auth = new BearerTokenExtractor().extract(request);
        if (auth != null) return getUsername(auth.getPrincipal());

        return null;
    }


    protected void setCookie(HttpServletResponse response, String idToken){
        String token= (String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,0);
        if (token==null)
            token=(String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,0);
        if (token==null)
            token=idToken;
        if (token!=null) {
            Cookie cookie = new Cookie(ID_TOKEN_PARAM, token);
            cookie.setSecure(true);
            cookie.setMaxAge(120);
            response.addCookie(cookie);
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

    @Override
    protected Authentication createAuthenticationForUser(String userName, String credentials, Object rawUser) {
        return createPreAuthentication(userName, getHttpRequest(), getHttpResponse());
    }

    protected PreAuthenticatedAuthenticationToken createPreAuthentication(String username, HttpServletRequest request, StatusResponseWrapper response){
        User user=retrieveUserWithAuthorities(username,request,response);
        SimpleGrantedAuthority authority=new SimpleGrantedAuthority("ROLE_"+user.getRole().toString());
        PreAuthenticatedAuthenticationToken authenticationToken=new PreAuthenticatedAuthenticationToken(user,null, Arrays.asList(authority));
        authenticationToken.setDetails(new WebAuthenticationDetails(request));
        return authenticationToken;
    }

    protected User retrieveUserWithAuthorities(String username, HttpServletRequest request, StatusResponseWrapper response){
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

    protected abstract String retrieveUserFromJWT(String token);

}
