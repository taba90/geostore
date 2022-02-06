package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.apache.commons.lang.time.DateUtils;
import org.apache.cxf.jaxrs.impl.ResponseBuilderImpl;
import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Configuration.CONFIG_NAME_SUFFIX;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.REFRESH_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getAccessToken;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getRefreshAccessToken;

/**
 * This class provides authentication entry point to login using an OAuth2 provider.
 */
public class OAuthLoginRestImpl implements OAuthLoginRest, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private final static Logger LOGGER = Logger.getLogger(OAuthLoginRestImpl.class);


    @Override
    public void login(String provider) {
        HttpServletResponse resp = OAuthUtils.getResponse();
        OAuth2Configuration configuration = configuration(provider);
        String login = configuration.buildLoginUri("offline");
        try {
            resp.sendRedirect(login);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Response callback(String provider) throws NotFoundWebEx {
        Response.ResponseBuilder result = new ResponseBuilderImpl();
        String token = getAccessToken();
        String refreshToken = getRefreshAccessToken();
        OAuth2Configuration configuration = configuration(provider);
        if (token != null) {
            try {
                result = result.status(302)
                        .location(new URI(configuration.getInternalRedirectUri()));
                if (token != null) result = result.cookie(cookie(ACCESS_TOKEN_PARAM, token));
                if (refreshToken != null) result = result.cookie(cookie(REFRESH_TOKEN_PARAM, refreshToken));
            } catch (URISyntaxException e) {
                result = result
                        .status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity("Exception while parsing the internal redirect url: " + e.getMessage());
            }
        } else {
            result = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("No access token found.");
        }
        return result.build();
    }

    private NewCookie cookie(String name, String value) {
        Cookie cookie = new Cookie(name, value, "/", null);
        return new AccessCookie(cookie, "", 60 * 60 * 24 * 1000, DateUtils.addDays(new Date(), 1), false, false, "lax");
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    private OAuth2Configuration configuration(String provider) {
        return (OAuth2Configuration) applicationContext.getBean(provider + CONFIG_NAME_SUFFIX);
    }
}
