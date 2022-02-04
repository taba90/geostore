package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.security.password.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

public class OAuthUtils {

    public static final String ID_TOKEN_PARAM ="id_token";

    public static final String ACCESS_TOKEN_PARAM ="access_token";

    public static final String REFRESH_TOKEN_PARAM ="refresh_token";


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

    static String getIdToken(){
        return getToken(OpenIdRestTemplate.ID_TOKEN_VALUE);
    }

    static String getAccessToken(){
        String token= getToken(ACCESS_TOKEN_PARAM);
        if (token==null) token=tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM,getRequest());
        return token;
    }

    static String getRefreshAccessToken(){
        String refreshToken=getToken(REFRESH_TOKEN_PARAM);
        if (refreshToken==null)
            refreshToken=getParameterValue(REFRESH_TOKEN_PARAM,getRequest());
        return refreshToken;

    }

    static TokenDetails getTokenDetails(Authentication authentication){
            TokenDetails tokenDetails=null;
            if (authentication!=null) {
                Object details = authentication.getDetails();
                if (details instanceof TokenDetails) {
                    tokenDetails = ((TokenDetails) details);
                }
            }
            return tokenDetails;
    }

    static HttpServletRequest getRequest() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getRequest();
    }

    static HttpServletResponse getResponse(){
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getResponse();
    }
}
