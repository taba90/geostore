package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.core.model.User;
import it.geosolutions.geostore.core.model.UserGroup;
import it.geosolutions.geostore.core.model.enums.Role;
import it.geosolutions.geostore.core.security.password.SecurityUtils;
import it.geosolutions.geostore.services.UserService;
import it.geosolutions.geostore.services.exception.BadRequestServiceEx;
import it.geosolutions.geostore.services.exception.NotFoundServiceEx;
import org.apache.log4j.Logger;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.REFRESH_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.getRequest;

/**
 * GeoStore custom Authentication  provider. It is used to map a Keycloak Authentication to a GeoStore Authentication where
 * the principal is of type {@link User}.
 */
public class GeoStoreKeycloakAuthProvider implements AuthenticationProvider {

    private GeoStoreKeycloakAuthoritiesMapper grantedAuthoritiesMapper;

    private final static Logger LOGGER = Logger.getLogger(GeoStoreKeycloakAuthProvider.class);


    @Autowired
    private UserService userService;

    private KeyCloakConfiguration configuration;

    public GeoStoreKeycloakAuthProvider (KeyCloakConfiguration configuration){
        this.configuration=configuration;
    }

    public void setGrantedAuthoritiesMapper(GeoStoreKeycloakAuthoritiesMapper grantedAuthoritiesMapper) {
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
        OidcKeycloakAccount account=token.getAccount();
        KeycloakSecurityContext context=account.getKeycloakSecurityContext();
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for (String role : token.getAccount().getRoles()) {
            grantedAuthorities.add(new KeycloakRole(role));
        }
        Collection<? extends GrantedAuthority> mapped=mapAuthorities(grantedAuthorities);

        AccessToken accessToken=context.getToken();
        String accessTokenStr=context.getTokenString();
        String refreshToken=null;
        Long  expiration=null;
        HttpServletRequest request=getRequest();
        if (accessToken!=null) {
            expiration = accessToken.getExp();
            if (request!=null) request.setAttribute(ACCESS_TOKEN_PARAM,accessToken);
        }
        if (context instanceof RefreshableKeycloakSecurityContext) {
            refreshToken = ((RefreshableKeycloakSecurityContext) context).getRefreshToken();
            if (request!=null) request.setAttribute(REFRESH_TOKEN_PARAM,refreshToken);
        }
        KeycloakTokenDetails details=new KeycloakTokenDetails(accessTokenStr,refreshToken,expiration);
        String username= getUsername(authentication);
        User user= retrieveUser(username,"");
        if (grantedAuthoritiesMapper!=null) user.getGroups().addAll(grantedAuthoritiesMapper.getGroups());
        if (grantedAuthoritiesMapper!=null) user.setRole(grantedAuthoritiesMapper.getRole());
        if (user.getRole()==null) user.setRole(configuration.getAuthenticatedDefaultRole());
        if (user.getRole()==null) user.setRole(Role.USER);
        PreAuthenticatedAuthenticationToken result= new PreAuthenticatedAuthenticationToken(user,"",mapped);
        result.setDetails(details);
        return result;
    }

    private Collection<? extends GrantedAuthority> mapAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        return grantedAuthoritiesMapper != null
                ? grantedAuthoritiesMapper.mapAuthorities(authorities)
                : authorities;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return KeycloakAuthenticationToken.class.isAssignableFrom(aClass);
    }

    /**
     * Retrieve the user from db or create a new instance. If {@link KeyCloakConfiguration#isAutoCreateUser()} returns
     * true, will insert the user in the db.
     * @param userName
     * @param credentials
     * @return
     */
    protected User retrieveUser(String userName, String credentials){
        User user = null;
        if (userService!=null){
            try {
                user=userService.get(userName);
            } catch (NotFoundServiceEx e){
                if (LOGGER.isDebugEnabled()){
                    LOGGER.warn("Keycloak user not found in DB.",e);
                }
            }
        }
        if (user==null) {
            user =new User();
            user.setName(userName);
            user.setNewPassword(credentials);
            user.setEnabled(true);
            user.setRole(configuration.getAuthenticatedDefaultRole());
            if (user.getRole()==null) user.setRole(Role.USER);
            Set<UserGroup> groups = new HashSet<UserGroup>();
            user.setGroups(groups);
            if (userService != null && configuration.isAutoCreateUser()) {
                try {
                    long id=userService.insert(user);
                    user=new User(user);
                    user.setId(id);
                } catch (NotFoundServiceEx | BadRequestServiceEx e) {
                    LOGGER.error("Exception while inserting the user.", e);
                }
            }
        }
        return user;
    }

    private String getUsername(Authentication authentication){
        String username=null;
        if (authentication !=null && authentication.getDetails() instanceof SimpleKeycloakAccount) {
            SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
            AccessToken token = account.getKeycloakSecurityContext().getToken();
            if (token !=null) username=token.getPreferredUsername();
        }
        if(username==null) username=SecurityUtils.getUsername(authentication);
        return username;
    }
}
