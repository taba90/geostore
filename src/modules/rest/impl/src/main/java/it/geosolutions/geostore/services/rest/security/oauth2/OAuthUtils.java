package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.security.password.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

public class OAuthUtils {

    public static final String ID_TOKEN_PARAM ="id_token";

    public static final String ACCESS_TOKEN_PARAM ="access_token";

    public static String tokenFromParamsOrBearer(String paramName, HttpServletRequest request){
        String token =getParameterValue(paramName,request);
        if (token ==null){
            token=getBearerToken(request);
        }
        return token;
    }
    public static String getParameterValue(String paramName, HttpServletRequest request) {
        for (Enumeration<String> iterator = request.getParameterNames();
             iterator.hasMoreElements(); ) {
            final String param = iterator.nextElement();
            if (paramName.equalsIgnoreCase(param)) {
                return request.getParameter(param);
            }
        }

        return null;
    }

    public static String getBearerToken(HttpServletRequest request) {
        Authentication auth = new BearerTokenExtractor().extract(request);
        if (auth != null) return SecurityUtils.getUsername(auth.getPrincipal());

        return null;
    }

    public static String getToken(String name){
        String token= (String) RequestContextHolder.getRequestAttributes().getAttribute(name,0);
        if (token==null)
            token=(String) RequestContextHolder.getRequestAttributes().getAttribute(name,1);
        return token;
    }

    public static String getIdToken(){
        return getToken(OpenIdRestTemplate.ID_TOKEN_VALUE);
    }

    public static String getAccessToken(){
        Authentication authentication=SecurityContextHolder.getContext().getAuthentication();
        TokenDetails details=getTokenDetails(authentication);
        String token=null;
        if (details!=null){
            token=details.getAccessToken().getValue();
        }
        return token;
    }

    static TokenDetails getTokenDetails(Authentication authentication){
            TokenDetails tokenDetails=null;
            Object details=authentication.getDetails();
            if (details instanceof TokenDetails){
                tokenDetails=((TokenDetails)details);
            }
            return tokenDetails;
    }
}
