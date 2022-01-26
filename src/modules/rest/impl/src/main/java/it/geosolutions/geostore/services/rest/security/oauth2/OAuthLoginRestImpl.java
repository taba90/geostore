package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.apache.commons.lang.time.DateUtils;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.ws.rs.core.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthGeoStoreSecurityConfiguration.OAUTH2CONFIG;
import static it.geosolutions.geostore.services.rest.security.oauth2.OpenIdGeoStoreAuthenticationFilter.ID_TOKEN_PARAM;

public class OAuthLoginRestImpl implements OAuthLoginRest, ApplicationContextAware {

    private ApplicationContext applicationContext;

    @Override
    public void login(String provider){
        HttpServletResponse resp=((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getResponse();
        OAuth2Configuration configuration=(OAuth2Configuration) applicationContext.getBean(provider+OAUTH2CONFIG);
        String login=configuration.buildLoginUri();
        try {
            resp.sendRedirect(login);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Response callback(String provider) throws NotFoundWebEx {
        Response result;
        String token= (String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,0);
        if (token==null)
            token=(String) RequestContextHolder.getRequestAttributes().getAttribute(OpenIdRestTemplate.ID_TOKEN_VALUE,1);
        if (token!=null) {
            OAuth2Configuration configuration=(OAuth2Configuration) applicationContext.getBean(provider+OAUTH2CONFIG);
            NewCookie cookie = new NewCookie(new Cookie(ID_TOKEN_PARAM,token),"",120, DateUtils.addMinutes(new Date(), 2),true,true);
            try {
                result= Response.status(302)
                        .location(new URI(configuration.getInternalRedirectUri()))
                        .cookie(cookie)
                        .build();
            } catch (URISyntaxException e) {
                result=Response
                        .status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity("Exception while parsing the internal redirect url: "+e.getMessage())
                        .build();
            }
        } else {
            result=Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("No token id found.")
                    .build();
        }
        return result;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext=applicationContext;
    }
}
