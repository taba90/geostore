package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeyCloakLoginRestImpl implements KeyCloakLoginRest, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private KeyCloakHelper keyCloakHelper;


    @Override
    public void login() {
        initKeycloakContext();
        HttpServletRequest request=OAuth2Utils.getRequest();
        HttpServletResponse response=OAuth2Utils.getResponse();
        RequestAuthenticator authenticator=keyCloakHelper.getAuthenticator(request,response);
        AuthChallenge challenge=authenticator.getChallenge();
        if (challenge.)

    }

    private void initKeycloakContext(){

    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext=applicationContext;
    }
}
