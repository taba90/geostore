package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.IOException;

import static it.geosolutions.geostore.services.rest.security.oauth2.OpenIdGeoStoreAuthenticationFilter.ID_TOKEN_PARAM;

public class OAuthLoginRestImpl implements OAuthLoginRest, ApplicationContextAware {

    private ApplicationContext applicationContext;

    @Override
    public void login(){
        HttpServletResponse resp=((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getResponse();
        OAuth2Configuration configuration=applicationContext.getBean(OAuth2Configuration.class);
        String login=configuration.buildloginUri();
        try {
            resp.sendRedirect(login);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Response callback() throws NotFoundWebEx {
        HttpServletResponse response=((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getResponse();
            String token= (String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,0);
            if (token==null)
                token=(String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,1);
            if (token!=null) {
                Cookie cookie = new Cookie(ID_TOKEN_PARAM, token);
                cookie.setSecure(true);
                cookie.setMaxAge(120);
                response.addCookie(cookie);
                return Response.ok().build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext=applicationContext;
    }
}
