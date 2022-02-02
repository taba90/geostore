package it.geosolutions.geostore.services.rest.security.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import it.geosolutions.geostore.services.exception.InternalErrorServiceEx;
import it.geosolutions.geostore.services.rest.exception.BadRequestWebEx;
import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import javax.ws.rs.core.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthGeoStoreSecurityConfiguration.OAUTH2CONFIG;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.REFRESH_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getAccessToken;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getParameterValue;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getRefreshAccessToken;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.getRequest;

public class OAuthLoginRestImpl implements OAuthLoginRest, ApplicationContextAware {

    private ApplicationContext applicationContext;

    private final static Logger LOGGER = Logger.getLogger(OAuthLoginRestImpl.class);


    @Override
    public void login(String provider){
        HttpServletResponse resp=OAuthUtils.getResponse();
        OAuth2Configuration configuration=configuration(provider);
        String login=configuration.buildLoginUri("offline");
        try {
            resp.sendRedirect(login);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Response callback(String provider) throws NotFoundWebEx {
        Response result;
        String token= getAccessToken();
        String refreshToken=getRefreshAccessToken();
        OAuth2Configuration configuration=configuration(provider);
        if (token!=null) {
            try {
                Response.ResponseBuilder builder= Response.status(302)
                        .location(new URI(configuration.getInternalRedirectUri()));
                if (token!=null) builder=builder.cookie(cookie(ACCESS_TOKEN_PARAM,token));
                if (refreshToken!=null) builder=builder.cookie(cookie(REFRESH_TOKEN_PARAM,refreshToken));
                result=builder.build();
            } catch (URISyntaxException e) {
                result=Response
                        .status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity("Exception while parsing the internal redirect url: "+e.getMessage())
                        .build();
            }
        } else {
            result=Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("No access token found.")
                    .build();
        }
        return result;
    }

    @Override
    public Response refresh(String provider, InputStream is) throws NotFoundWebEx {
        ObjectNode json=parseStream(is);
        String accessToken=json.has(ACCESS_TOKEN_PARAM)?json.get(ACCESS_TOKEN_PARAM).asText():null;
        HttpServletRequest request=getRequest();
        if (accessToken==null) accessToken=OAuthUtils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM,request);
        if (accessToken==null) throw new NotFoundWebEx("Either the accessToken or the refresh token are missing");

        OAuth2AccessToken currentToken=retrieveAccessToken(accessToken);
        Date expiresIn=currentToken.getExpiration();
        String refreshToken=json.has(REFRESH_TOKEN_PARAM)?json.get(REFRESH_TOKEN_PARAM).asText():null;

        if (refreshToken==null) refreshToken=getParameterValue(REFRESH_TOKEN_PARAM,request);
        Date fiveMinutesFromNow=fiveMinutesFromNow();
        Response.ResponseBuilder builder =null;
        if ((expiresIn==null || fiveMinutesFromNow.after(expiresIn)) && refreshToken!=null) {
            OAuth2Configuration configuration = configuration(provider);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            form.add("client_secret", configuration.getClientSecret());
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            OAuth2AccessToken newToken = restTemplate.execute(configuration.buildRefreshTokenURI("offline"), HttpMethod.POST, new RefreshTokenRequestCallback(form, headers), responseExtractor());
            if (newToken != null && newToken.getValue()!=null) {
                String refreshed = newToken.getValue();
                rebuildTokenAuth(accessToken, newToken, refreshToken);
                builder=Response.status(201).entity(writeJSON(refreshed,refreshToken));

            }
        }
        if (builder==null) builder=Response.status(200).entity(writeJSON(accessToken,refreshToken));
        return builder.build();
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

    private Date fiveMinutesFromNow(){
        Calendar currentTimeNow = Calendar.getInstance();
        System.out.println("Current time now : " + currentTimeNow.getTime());
        currentTimeNow.add(Calendar.MINUTE, 5);
        return currentTimeNow.getTime();
    }

    @Override
    public Response logout(String provider) throws NotFoundWebEx {
        HttpServletRequest request=OAuthUtils.getRequest();
        HttpServletResponse response=OAuthUtils.getResponse();
        OAuth2RestTemplate restTemplate=applicationContext.getBean(OAuth2RestTemplate.class);
        String accessToken=OAuthUtils.tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM, request);
        OAuth2Cache cache=cache();
        cache.removeEntry(accessToken);
        Response.ResponseBuilder builder=Response.status(HttpStatus.NO_CONTENT.value());
        OAuth2AccessToken token = restTemplate.getOAuth2ClientContext().getAccessToken();
        if (token != null) {
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
        clearCookies(request,response,builder);
        return builder.build();
    }

    private void clearCookies(HttpServletRequest request, HttpServletResponse response, Response.ResponseBuilder builder){
        javax.servlet.http.Cookie[] allCookies = request.getCookies();
        if (allCookies!=null && allCookies.length>0)
            for (int i = 0; i < allCookies.length; i++) {
                javax.servlet.http.Cookie toDelete = allCookies[i];
                if (deleteCookie(toDelete)) {
                    toDelete.setMaxAge(-1);
                    toDelete.setPath("/");
                    toDelete.setComment("EXPIRING COOKIE at " + System.currentTimeMillis());
                    Cookie cookie=new Cookie(toDelete.getName(),toDelete.getValue(),toDelete.getPath(),toDelete.getDomain());
                    builder.cookie(new NewCookie(cookie,toDelete.getComment(),toDelete.getMaxAge(),false));
                    response.addCookie(toDelete);
                }
            }
    }

    private boolean deleteCookie(javax.servlet.http.Cookie c){
        return c.getName().equalsIgnoreCase("JSESSIONID") || c.getName().equalsIgnoreCase(ACCESS_TOKEN_PARAM) || c.getName().equalsIgnoreCase(REFRESH_TOKEN_PARAM);
    }

    private String writeJSON(String accessToken, String refreshToken ) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String,String> map=new HashMap<>(2);
            map.put(ACCESS_TOKEN_PARAM,accessToken);
            if (refreshToken!=null)
                map.put(REFRESH_TOKEN_PARAM,refreshToken);
            return objectMapper.writeValueAsString(map);
        } catch (IOException e){
            throw new RuntimeException("Error while parsing the JSON payload. The JSON is likely malformed.",e);
        }
    }

    private ObjectNode parseStream(InputStream is){
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(is);
            if (!(jsonNode instanceof ObjectNode)) {
                throw new BadRequestWebEx("Unsupported JSON in request payload. It should be a JSON object");
            }
            ObjectNode objectNode = (ObjectNode) jsonNode;
            if (!jsonNode.has(ACCESS_TOKEN_PARAM) || !jsonNode.has(REFRESH_TOKEN_PARAM)) {
                throw new BadRequestWebEx("Either the access token or refresh token are not provided in the request body.");
            }
            return objectNode;
        } catch (IOException e){
            throw new BadRequestWebEx("Error while parsing the JSON payload. The JSON is likely malformed.");
        }
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

    private NewCookie cookie(String name, String value){
        Cookie cookie=new Cookie(name,value,"/",null);
        return new NewCookie(cookie,"",60*60*24*1000, DateUtils.addDays(new Date(), 1),false,false);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext=applicationContext;
    }

    public HttpMessageConverterExtractor<OAuth2AccessToken> responseExtractor(){
        return new HttpMessageConverterExtractor<>(OAuth2AccessToken.class,restTemplate().getMessageConverters());
    }

    private OAuth2Configuration configuration(String provider){
        return (OAuth2Configuration) applicationContext.getBean(provider+OAUTH2CONFIG);
    }

    private OAuth2RestTemplate restTemplate(){
        return applicationContext.getBean(OAuth2RestTemplate.class);
    }

    private class RefreshTokenRequestCallback implements RequestCallback{

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
            LOGGER.debug("Encoding and sending form: " + form);
            new FormHttpMessageConverter().write(this.form, MediaType.APPLICATION_FORM_URLENCODED, request);
        }
    }

    private OAuth2Cache cache(){
        return applicationContext.getBean(OAuth2Cache.class);
    }
}
