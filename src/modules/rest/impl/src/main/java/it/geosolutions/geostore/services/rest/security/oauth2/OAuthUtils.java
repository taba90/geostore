package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.security.password.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

public class OAuthUtils {

    static String tokenFromParamsOrBearer(String paramName, HttpServletRequest request){
        String token =getParameterValue(paramName,request);
        if (token ==null){
            token=getBearerToken(request);
        }
        return token;
    }
    static String getParameterValue(String paramName, HttpServletRequest request) {
        for (Enumeration<String> iterator = request.getParameterNames();
             iterator.hasMoreElements(); ) {
            final String param = iterator.nextElement();
            if (paramName.equalsIgnoreCase(param)) {
                return request.getParameter(param);
            }
        }

        return null;
    }

    static String getBearerToken(HttpServletRequest request) {
        Authentication auth = new BearerTokenExtractor().extract(request);
        if (auth != null) return SecurityUtils.getUsername(auth.getPrincipal());

        return null;
    }
}
