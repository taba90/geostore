package it.geosolutions.geostore.services.rest.security.keycloak;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticator;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeyCloakHelper {

    private final SpringSecurityAdapterTokenStoreFactory adapterTokenStoreFactory;
    private AdapterDeploymentContext keycloakContext;

    public KeyCloakHelper(AdapterDeploymentContext keycloakContext){
        this.adapterTokenStoreFactory=new SpringSecurityAdapterTokenStoreFactory();
        this.keycloakContext=keycloakContext;
    }

    public KeycloakDeployment getDeployment(HttpServletRequest request,HttpServletResponse response){
        HttpFacade exchange = new SimpleHttpFacade(request, response);
        KeycloakDeployment deployment = keycloakContext.resolveDeployment(exchange);
        deployment.setDelegateBearerErrorResponseSending(true);
        return deployment;
    }

    public RequestAuthenticator getAuthenticator(HttpServletRequest request, HttpServletResponse response, KeycloakDeployment deployment){
        request =
                new KeyCloakRequestWrapper(request);
        AdapterTokenStore tokenStore =
                adapterTokenStoreFactory.createAdapterTokenStore(deployment, request);
        SimpleHttpFacade simpleHttpFacade=new SimpleHttpFacade(request,response);
        return
                new SpringSecurityRequestAuthenticator(
                        simpleHttpFacade, request, deployment, tokenStore, -1);
    }
}
