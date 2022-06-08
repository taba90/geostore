package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.services.rest.IdPLoginRest;
import it.geosolutions.geostore.services.rest.security.oauth2.Oauth2LoginService;
import it.geosolutions.geostore.services.rest.utils.GeoStoreContext;
import org.apache.log4j.Logger;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class KeyCloakLoginService extends Oauth2LoginService {

    private KeyCloakHelper keyCloakHelper;

    private final static Logger LOGGER = Logger.getLogger(KeyCloakLoginService.class);

    static String KEYCLOAK_REDIRECT="KEYCLOAK_REDIRECT";

    public KeyCloakLoginService(IdPLoginRest loginRest){
        loginRest.registerService("keycloak",this);
    }

    @Override
    public void doLogin(HttpServletRequest request, HttpServletResponse response, String provider) {
        initHelper();
        if (doRedirect()) {
            KeycloakDeployment deployment = keyCloakHelper.getDeployment(request, response);
            RequestAuthenticator authenticator = keyCloakHelper.getAuthenticator(request, response, deployment);
            authenticator.authenticate();
            AuthChallenge challenge = authenticator.getChallenge();
            challenge.challenge(new SimpleHttpFacade(request, response));
            try {
                response.sendRedirect(response.getHeader("Location"));
            } catch (IOException e) {
            }
        } else {
            /*for (Cookie cookie:request.getCookies()){
                String name=cookie.getName();
                if (name.equals(ACCESS_TOKEN_PARAM) || name.equals(REFRESH_TOKEN_PARAM)) {
                    Cookie newCookie=new Cookie(cookie.getName(),cookie.getValue());
                    newCookie.setMaxAge(60 * 60 * 24 * 1000);
                    newCookie.setSecure(false);
                    newCookie.setPath(cookie.getPath());
                    response.addCookie(newCookie);
                }
            }*/
            try {
                response.sendRedirect(configuration(provider).getInternalRedirectUri());
            }catch (IOException e){
                LOGGER.error("Error while redirecting to internal url...",e);
                throw new RuntimeException(e);
            }
        }
    }

    private boolean doRedirect(){
        Object redirect=RequestContextHolder.getRequestAttributes().getAttribute(KEYCLOAK_REDIRECT,0);
        if (redirect!=null)
            return ((Boolean) redirect).booleanValue();
        return false;
    }

    private void initHelper(){
        if (keyCloakHelper==null){
            keyCloakHelper= GeoStoreContext.bean(KeyCloakHelper.class);
        }
    }
}
