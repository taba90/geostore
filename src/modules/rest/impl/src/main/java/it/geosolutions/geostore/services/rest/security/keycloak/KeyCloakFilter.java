package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.services.rest.security.GeoStoreAuthenticationFilter;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticator;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.keycloak.authorization.client.util.Http;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class KeyCloakFilter extends GenericFilterBean {


    // used to map keycloak roles to spring-security roles
    private final KeycloakAuthenticationProvider authenticationMapper;
    // creates token stores capable of generating spring-security tokens from keycloak auth
    // the context of the keycloak environment (realm, URL, client-secrets etc.)
    private KeyCloakHelper helper;

    public KeyCloakFilter (KeyCloakHelper helper){
        this.helper=helper;
        this.authenticationMapper = new KeycloakAuthenticationProvider();
        SimpleAuthorityMapper simpleAuthMapper = new SimpleAuthorityMapper();
        simpleAuthMapper.setPrefix("");
        authenticationMapper.setGrantedAuthoritiesMapper(simpleAuthMapper);
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        getNewAuthentication((HttpServletRequest) request,(HttpServletResponse) response);
        chain.doFilter(request,response);
    }

    protected void getNewAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // do some setup and create the authenticator
        RequestAuthenticator authenticator = helper.getAuthenticator(request,response);
        // perform the authentication operation
        AuthOutcome result = authenticator.authenticate();
        AuthChallenge challenge = authenticator.getChallenge();
        Authentication authentication = null;
        switch (result) {
            case AUTHENTICATED:
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                authentication = authenticationMapper.authenticate(auth);
            default:
                // do nothing
        }
    }
}
