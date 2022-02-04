package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.services.rest.RESTSessionService;
import it.geosolutions.geostore.services.rest.SessionServiceDelegate;
import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import it.geosolutions.geostore.services.rest.model.SessionToken;
import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.REFRESH_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getParameterValue;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getRequest;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getResponse;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getTokenDetails;

public abstract class OAuthSessionServiceDelegate implements SessionServiceDelegate, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private final static Logger LOGGER = Logger.getLogger(OAuthSessionServiceDelegate.class);


    public OAuthSessionServiceDelegate(RESTSessionService restSessionService,String delegateName){
        restSessionService.registerDelegate(delegateName,this);
    }


    @Override
    public SessionToken refresh(String refreshToken, String accessToken) {
        HttpServletRequest request=getRequest();
        if (accessToken==null) accessToken=OAuthUtils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM,request);
        if (accessToken==null) throw new NotFoundWebEx("Either the accessToken or the refresh token are missing");

        OAuth2AccessToken currentToken=retrieveAccessToken(accessToken);
        Date expiresIn=currentToken.getExpiration();
        if (refreshToken==null) refreshToken=getParameterValue(REFRESH_TOKEN_PARAM,request);
        Date fiveMinutesFromNow=fiveMinutesFromNow();
        SessionToken sessionToken=null;
        OAuth2Configuration configuration = configuration();
        if ((expiresIn==null || fiveMinutesFromNow.after(expiresIn)) && refreshToken!=null) {
            doRefresh(refreshToken,accessToken, configuration);
        }
        if(sessionToken==null)
            sessionToken=sessionToken(accessToken,refreshToken,currentToken.getExpiration());
        return sessionToken;
    }

    protected SessionToken doRefresh(String refreshToken, String accessToken, OAuth2Configuration configuration){
        SessionToken sessionToken=null;
        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("client_secret", configuration.getClientSecret());
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        OAuth2AccessToken newToken = restTemplate.execute(configuration.buildRefreshTokenURI("offline"), HttpMethod.POST, new RefreshTokenRequestCallback(form, headers), tokenExtractor());
        if (newToken != null && newToken.getValue()!=null) {
            String refreshed = newToken.getValue();
            rebuildTokenAuth(accessToken, newToken, refreshToken);
            sessionToken=sessionToken(refreshed,refreshToken,newToken.getExpiration());
        } else {
            LOGGER.info("Unable to refresh the token. The following request was performed: "+ configuration.buildRefreshTokenURI("offline")+". Redirecting to login.");
            doLogout(null);
            try {
                getResponse().sendRedirect("../../openid/" + configuration.getProvider().toLowerCase() + "/login");
            } catch (IOException e){
                LOGGER.error("Error while sending redirect to login service. ",e);
                throw new RuntimeException(e);
            }
        }
        return sessionToken;
    }

    private SessionToken sessionToken(String accessToken, String refreshToken, Date expires){
        SessionToken sessionToken=new SessionToken();
        sessionToken.setExpires(Long.valueOf(expires.getTime()));
        sessionToken.setAccessToken(accessToken);
        sessionToken.setRefreshToken(refreshToken);
        sessionToken.setTokenType("bearer");
        return sessionToken;
    }

    private Authentication rebuildTokenAuth(String oldToken, OAuth2AccessToken newToken, String refreshToken){
        Authentication authentication=cache().get(oldToken);
        if (newToken!=null) {
            if (authentication == null)
                authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof PreAuthenticatedAuthenticationToken) {
                String idToken=null;
                TokenDetails details=OAuthUtils.getTokenDetails(authentication);
                idToken=details.getIdToken();
                cache().removeEntry(oldToken);
                PreAuthenticatedAuthenticationToken updated = new PreAuthenticatedAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authentication.getAuthorities());
                DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(newToken);
                if (refreshToken != null) {
                    accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
                }
                updated.setDetails(new TokenDetails(accessToken,idToken));
                cache().putCacheEntry(newToken.getValue(),updated);
                SecurityContextHolder.getContext().setAuthentication(updated);
                authentication=updated;
            }
        }
        return authentication;
    }

    private Date fiveMinutesFromNow(){
        Calendar currentTimeNow = Calendar.getInstance();
        System.out.println("Current time now : " + currentTimeNow.getTime());
        currentTimeNow.add(Calendar.MINUTE, 5);
        return currentTimeNow.getTime();
    }

    private OAuth2AccessToken retrieveAccessToken(String accessToken){
        Authentication authentication=cache().get(accessToken);
        OAuth2AccessToken result=null;
        if (authentication!=null){
            TokenDetails details=OAuthUtils.getTokenDetails(authentication);
            result=details.getAccessToken();
        }
        if (result==null){
            OAuth2ClientContext context=applicationContext.getBean(OAuth2RestTemplate.class).getOAuth2ClientContext();
            if (context!=null) result=context.getAccessToken();
        }
        if (result==null)
            result=new DefaultOAuth2AccessToken(accessToken);
        return result;
    }

    @Override
    public void doLogout(String accessToken) {
        HttpServletRequest request=OAuthUtils.getRequest();
        HttpServletResponse response= getResponse();
        OAuth2RestTemplate restTemplate=applicationContext.getBean(OAuth2RestTemplate.class);
        if (accessToken==null)
            accessToken=OAuthUtils.getParameterValue(ACCESS_TOKEN_PARAM,getRequest());
        OAuth2Cache cache=cache();
        Authentication authentication=cache.get(accessToken);
        OAuth2AccessToken token=null;
        TokenDetails tokenDetails=getTokenDetails(authentication);
        if (tokenDetails!=null) token=tokenDetails.getAccessToken();
        cache.removeEntry(accessToken);
        if (token==null)
            token = restTemplate.getOAuth2ClientContext().getAccessToken();
        if (token != null) {
            revokeAuthorization(token);
            final AccessTokenRequest accessTokenRequest =
                    restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
            if (accessTokenRequest != null && accessTokenRequest.getStateKey() != null) {
                restTemplate
                        .getOAuth2ClientContext()
                        .removePreservedState(accessTokenRequest.getStateKey());
            }
            try {
                accessTokenRequest.remove("access_token");
                accessTokenRequest.remove("refresh_token");
            } finally {
                SecurityContextHolder.clearContext();
                request.getSession(false).invalidate();
            }
        }
        clearCookies(request,response);
    }

    protected void revokeAuthorization(OAuth2AccessToken token){
        String tokenValue=token.getRefreshToken()!=null?token.getRefreshToken().getValue():token.getValue();
        OAuth2Configuration configuration=configuration();
        if (configuration.getRevokeEndpoint()!=null && tokenValue!=null){
            callRevokeEndpoint(tokenValue,configuration.getRevokeEndpoint());
        }
    }

    protected abstract void callRevokeEndpoint(String token, String url);

    protected void clearCookies(HttpServletRequest request, HttpServletResponse response){
        javax.servlet.http.Cookie[] allCookies = request.getCookies();
        if (allCookies!=null && allCookies.length>0)
            for (int i = 0; i < allCookies.length; i++) {
                javax.servlet.http.Cookie toDelete = allCookies[i];
                if (deleteCookie(toDelete)) {
                    toDelete.setMaxAge(-1);
                    toDelete.setPath("/");
                    toDelete.setComment("EXPIRING COOKIE at " + System.currentTimeMillis());
                    response.addCookie(toDelete);
                }
            }
    }

    protected boolean deleteCookie(javax.servlet.http.Cookie c){
        return c.getName().equalsIgnoreCase("JSESSIONID") || c.getName().equalsIgnoreCase(ACCESS_TOKEN_PARAM) || c.getName().equalsIgnoreCase(REFRESH_TOKEN_PARAM);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext=applicationContext;
    }

    protected OAuth2Cache cache(){
        return applicationContext.getBean(OAuth2Cache.class);
    }

    protected abstract OAuth2Configuration configuration();

    protected OAuth2Configuration configuration(String configBeanName){
        return (OAuth2Configuration) applicationContext.getBean(configBeanName);
    }

    protected class RefreshTokenRequestCallback implements RequestCallback {

        private final MultiValueMap<String, String> form;

        private final HttpHeaders headers;

        private RefreshTokenRequestCallback(MultiValueMap<String, String> form, HttpHeaders headers) {
            this.form = form;
            this.headers = headers;
        }

        public void doWithRequest(ClientHttpRequest request) throws IOException {
            request.getHeaders().putAll(this.headers);
            request.getHeaders().setAccept(
                    Arrays.asList(MediaType.APPLICATION_JSON,MediaType.TEXT_XML,MediaType.TEXT_PLAIN, MediaType.APPLICATION_FORM_URLENCODED));
            new FormHttpMessageConverter().write(this.form, MediaType.APPLICATION_FORM_URLENCODED, request);
        }
    }

    protected HttpMessageConverterExtractor<OAuth2AccessToken> tokenExtractor(){
        return new HttpMessageConverterExtractor<>(OAuth2AccessToken.class,restTemplate().getMessageConverters());
    }




    protected OAuth2RestTemplate restTemplate(){
        return applicationContext.getBean(OAuth2RestTemplate.class);
    }
}
