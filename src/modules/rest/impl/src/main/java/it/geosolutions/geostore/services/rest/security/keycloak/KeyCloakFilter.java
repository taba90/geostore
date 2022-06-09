package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.UserAttribute;
import it.geosolutions.geostore.core.model.UserGroup;
import it.geosolutions.geostore.core.model.enums.Role;
import it.geosolutions.geostore.core.security.password.SecurityUtils;
import it.geosolutions.geostore.services.UserGroupService;
import it.geosolutions.geostore.services.UserService;
import it.geosolutions.geostore.services.exception.BadRequestServiceEx;
import it.geosolutions.geostore.services.exception.NotFoundServiceEx;
import it.geosolutions.geostore.services.rest.security.GeoStoreAuthenticationFilter;
import it.geosolutions.geostore.services.rest.security.TokenAuthenticationCache;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils;
import it.geosolutions.geostore.services.rest.security.oauth2.TokenDetails;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.jaas.AbstractKeycloakLoginModule;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticator;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static it.geosolutions.geostore.services.rest.SessionServiceDelegate.PROVIDER_KEY;
import static it.geosolutions.geostore.services.rest.security.keycloak.KeyCloakLoginService.KEYCLOAK_REDIRECT;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.ACCESS_TOKEN_PARAM;

public class KeyCloakFilter extends GenericFilterBean {


    // used to map keycloak roles to spring-security roles
    private final KeycloakAuthenticationProvider authenticationMapper;
    // creates token stores capable of generating spring-security tokens from keycloak auth
    // the context of the keycloak environment (realm, URL, client-secrets etc.)
    private KeyCloakHelper helper;

    private KeyCloakConfiguration configuration;

    @Autowired
    protected UserService userService;

    @Autowired
    protected UserGroupService userGroupService;

    private TokenAuthenticationCache cache;

    public KeyCloakFilter (KeyCloakHelper helper, TokenAuthenticationCache cache, KeyCloakConfiguration configuration){
        this.helper=helper;
        this.authenticationMapper = new KeycloakAuthenticationProvider();
        SimpleAuthorityMapper simpleAuthMapper = new SimpleAuthorityMapper();
        simpleAuthMapper.setPrefix("");
        authenticationMapper.setGrantedAuthoritiesMapper(simpleAuthMapper);
        this.cache=cache;
        this.configuration=configuration;
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (enabledAndValid() && SecurityContextHolder.getContext().getAuthentication()==null) {
            Authentication authentication = authenticate((HttpServletRequest) request, (HttpServletResponse) response);
            if (authentication != null){
                SecurityContextHolder.getContext().setAuthentication(authentication);
                RequestContextHolder.getRequestAttributes().setAttribute(PROVIDER_KEY,"keycloak",0);
            }
        }
        chain.doFilter(request,response);
    }

    private boolean enabledAndValid(){
        return configuration.isEnabled() && configuration.getJsonConfig()!=null;
    }

    protected Authentication authenticateAndUpdateCache(HttpServletRequest request, HttpServletResponse response) {
        // do some setup and create the authenticator
        KeycloakDeployment deployment=helper.getDeployment(request,response);
        RequestAuthenticator authenticator = helper.getAuthenticator(request,response,deployment);
        // perform the authentication operation
        AuthOutcome result = authenticator.authenticate();
        Authentication auth=null;
        if (result.equals(AuthOutcome.AUTHENTICATED)) {
                auth = SecurityContextHolder.getContext().getAuthentication();
                //authentication = authenticationMapper.authenticate(auth);
                auth=authenticationMapper.authenticate(auth);
                auth=createPreAuth(auth,request,response);
                updateCache(auth);
        } else {
            RequestContextHolder.getRequestAttributes().setAttribute(KEYCLOAK_REDIRECT,true,0);
        }
        return auth;
    }

    protected void updateCache(Authentication authentication){
        Object details=authentication.getDetails();
        if (details instanceof KeycloakTokenDetails){
            KeycloakTokenDetails keycloakDetails=(KeycloakTokenDetails) details;
            String accessToken=keycloakDetails.getAccessToken();
            if (accessToken!=null){
                cache.putCacheEntry(accessToken,authentication);
            }
        }
    }

    protected Authentication authenticate(HttpServletRequest request,HttpServletResponse response){
        Authentication authentication=null;
        String token = OAuth2Utils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM, request);
        if (token != null) {
            authentication = cache.get(token);
            if (authentication!=null && authentication.getDetails() instanceof KeycloakTokenDetails){
                KeycloakTokenDetails details=(KeycloakTokenDetails) authentication.getDetails();
                if (details.getExpiration().before(new Date())){
                    tryRefresh(details.getRefreshToken(),details.getAccessToken());
                    authentication=cache.get(token);
                }
            }

            if (authentication == null) {
                authentication = authenticateAndUpdateCache(request, response);
            }
        } else {
            authentication=authenticateAndUpdateCache(request,response);
        }
        return authentication;
    }

    private void tryRefresh(String refreshToken, String oldAccessToken){
        if (refreshToken!=null) {
            AdapterConfig adapterConfig = configuration.readAdapterConfig();
            AccessTokenResponse response = helper.refreshToken(adapterConfig, refreshToken);
            String newAccessToken = response.getToken();
            long exp = response.getExpiresIn();
            String newRefreshToken = response.getRefreshToken();
            helper.updateAuthentication(cache, oldAccessToken, newAccessToken, newRefreshToken, exp);
        }
    }

    private Authentication createPreAuth(Authentication authentication, HttpServletRequest request,HttpServletResponse response){
            User user=retrieveUserWithAuthorities(SecurityUtils.getUsername(authentication.getPrincipal()),request,response);
            List<GrantedAuthority> authorities=new ArrayList<>();
            authorities.addAll(authentication.getAuthorities());
            authorities.add(new SimpleGrantedAuthority("ROLE_"+user.getRole().name()));
            PreAuthenticatedAuthenticationToken authenticationToken=new PreAuthenticatedAuthenticationToken(user,"",authorities);
            if (authentication.getDetails() instanceof OidcKeycloakAccount){
                OidcKeycloakAccount keycloakAccount=(OidcKeycloakAccount) authentication.getDetails();
                KeycloakSecurityContext context=keycloakAccount.getKeycloakSecurityContext();
                String accessToken=context.getTokenString();
                int expiration=context.getToken().getExpiration();
                String refreshToken=null;
                if (context instanceof RefreshableKeycloakSecurityContext){
                    refreshToken=((RefreshableKeycloakSecurityContext)context).getRefreshToken();
                }
                KeycloakTokenDetails details=new KeycloakTokenDetails(accessToken,refreshToken,expiration);
                authenticationToken.setDetails(details);
            }
            return authenticationToken;
    }

    /**
     * Retrieves a user by username. Will create the user when not found, if the auto create flag was set to true.
     * @param username the username.
     * @param request the HttpServletRequest.
     * @param response the HttpServletResponse.
     * @return a {@link User} instance if the user was found/created. Null otherwise.
     */
    protected User retrieveUserWithAuthorities(String username, HttpServletRequest request, HttpServletResponse response) {
        User user = null;
        if (username != null && userService!=null) {
            try {
                user = userService.get(username);
            } catch (NotFoundServiceEx notFoundServiceEx) {
            }
        }
        if (user == null) {
            try {
                user = createUser(username, null, "");
            } catch (BadRequestServiceEx | NotFoundServiceEx e) {
            }
        }
        return user;
    }

    /**
     * Create a User instance.
     * @param userName the username.
     * @param credentials the password.
     * @param rawUser user object.
     * @return a User instance.
     * @throws BadRequestServiceEx
     * @throws NotFoundServiceEx
     */
    protected User createUser(String userName, String credentials, Object rawUser) throws BadRequestServiceEx, NotFoundServiceEx {
        User user = new User();

        user.setName(userName);
        user.setNewPassword(credentials);
        user.setEnabled(true);
        Role role = Role.USER;
        user.setRole(role);
        Set<UserGroup> groups = new HashSet<UserGroup>();
        user.setGroups(groups);
        if (userService != null) {
            userService.insert(user);
        }
        return user;
    }

}
