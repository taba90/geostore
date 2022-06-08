package it.geosolutions.geostore.services.rest.security.keycloak;

import it.geosolutions.geostore.services.rest.RESTSessionService;
import it.geosolutions.geostore.services.rest.SessionServiceDelegate;
import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import it.geosolutions.geostore.services.rest.model.SessionToken;
import it.geosolutions.geostore.services.rest.security.TokenAuthenticationCache;
import it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils;
import it.geosolutions.geostore.services.rest.utils.GeoStoreContext;
import org.apache.log4j.Logger;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Map;

import static it.geosolutions.geostore.services.rest.security.keycloak.KeyCloakSecurityConfiguration.CACHE_BEAN_NAME;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.ACCESS_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.REFRESH_TOKEN_PARAM;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.getParameterValue;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.getRequest;
import static it.geosolutions.geostore.services.rest.security.oauth2.OAuth2Utils.tokenFromParamsOrBearer;

public class KeycloakSessionServiceDelegate implements SessionServiceDelegate {

    private final static Logger LOGGER = Logger.getLogger(KeycloakSessionServiceDelegate.class);

    public KeycloakSessionServiceDelegate(RESTSessionService restSessionService){
        restSessionService.registerDelegate("keycloak",this);
    }

    @Override
    public SessionToken refresh(String refreshToken, String accessToken) {
        HttpServletRequest request = getRequest();
        if (accessToken == null) accessToken = tokenFromParamsOrBearer(ACCESS_TOKEN_PARAM, request);
        if (accessToken == null) throw new NotFoundWebEx("The accessToken is missing");
        if (refreshToken == null) refreshToken = getParameterValue(REFRESH_TOKEN_PARAM, request);
        TokenAuthenticationCache cache=GeoStoreContext.bean(CACHE_BEAN_NAME,TokenAuthenticationCache.class);
        Date tokenExpiration=tokenExpirationTime(accessToken,cache);
        Date fiveMinutesFromNow=OAuth2Utils.fiveMinutesFromNow();
        SessionToken sessionToken;
        if (refreshToken!=null && (tokenExpiration==null || fiveMinutesFromNow.after(tokenExpiration)))
            sessionToken=doRefresh(accessToken,refreshToken,cache);
        else sessionToken=sessionToken(accessToken,refreshToken);
        return sessionToken;
    }

    private SessionToken doRefresh(String accessToken,String refreshToken,TokenAuthenticationCache cache){
        KeyCloakConfiguration configuration = GeoStoreContext.bean(KeyCloakConfiguration.class);
        AdapterConfig adapter = configuration.readAdapterConfig();
        Configuration clientConf = getClientConfiguration(adapter);
        String url = adapter.getAuthServerUrl() + "/realms/" + adapter.getRealm() + "/protocol/openid-connect/token";
        String clientId = adapter.getResource();
        String secret = (String) adapter.getCredentials().get("secret");
        Http http = new Http(clientConf, (params, headers) -> {
        });

        AccessTokenResponse response = http.<AccessTokenResponse>post(url)
                .authentication()
                .client()
                .form()
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken)
                .param("client_id", clientId)
                .param("client_secret", secret)
                .response()
                .json(AccessTokenResponse.class)
                .execute();
        String newAccessToken = response.getToken();
        long exp = response.getExpiresIn();
        String newRefreshToken = response.getRefreshToken();
        updateAuthentication(cache, accessToken, newAccessToken, newRefreshToken, exp);
        return sessionToken(newAccessToken,newRefreshToken);
    }

    private Date tokenExpirationTime(String accessToken, TokenAuthenticationCache cache){
        Date result=null;
        Authentication authentication=cache.get(accessToken);
        if(authentication!=null && authentication.getDetails() instanceof KeycloakTokenDetails){
            KeycloakTokenDetails details=(KeycloakTokenDetails) authentication.getDetails();
            result=details.getExpiration();
        }
        return result;
    }

    private SessionToken sessionToken(String accessToken, String refreshToken) {
        SessionToken sessionToken = new SessionToken();
        sessionToken.setAccessToken(accessToken);
        sessionToken.setRefreshToken(refreshToken);
        sessionToken.setTokenType("bearer");
        return sessionToken;
    }

    // Builds an authentication instance out of the passed values.
    // Sets it to the cache and to the SecurityContext to be sure the new token is updates.
    private Authentication updateAuthentication(TokenAuthenticationCache cache, String oldToken, String newToken, String refreshToken,long expiresIn) {
        Authentication authentication = cache.get(oldToken);
        if (authentication == null)
            authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof PreAuthenticatedAuthenticationToken) {
            if (LOGGER.isDebugEnabled())
                LOGGER.info("Updating the cache and the SecurityContext with new Auth details");
            cache.removeEntry(oldToken);
            PreAuthenticatedAuthenticationToken updated = new PreAuthenticatedAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authentication.getAuthorities());
            if (LOGGER.isDebugEnabled())
                LOGGER.debug("Updating keycloak details.");
            KeycloakTokenDetails details=new KeycloakTokenDetails(newToken,refreshToken,expiresIn);
            updated.setDetails(details);
            cache.putCacheEntry(newToken, updated);
            SecurityContextHolder.getContext().setAuthentication(updated);
            authentication = updated;
        }
        return authentication;
    }

    private Configuration getClientConfiguration(AdapterConfig config){
        String serverUrl=config.getAuthServerUrl();
        String realm=config.getRealm();
        String resource=config.getResource();
        Map<String,Object> credentials=config.getCredentials();
        return new Configuration(serverUrl,realm,resource,credentials,null);
    }
    @Override
    public void doLogout(String accessToken) {
        HttpServletRequest request= OAuth2Utils.getRequest();
        HttpServletResponse response=OAuth2Utils.getResponse();
        KeyCloakHelper helper=GeoStoreContext.bean(KeyCloakHelper.class);
        KeycloakDeployment deployment=helper.getDeployment(request,response);
        String logoutUrl=deployment
                .getLogoutUrl()
                .build()
                .toString();
        AdapterConfig adapterConfig=GeoStoreContext.bean(KeyCloakConfiguration.class).readAdapterConfig();
        Configuration clientConfiguration=getClientConfiguration(adapterConfig);
        Http http = new Http(clientConfiguration, (params, headers) -> {});
        String clientId = adapterConfig.getResource();
        String secret = (String) adapterConfig.getCredentials().get("secret");
        http.post(logoutUrl)
                .form()
                .param("client_id", clientId)
                .param("client_secret", secret)
                .execute();
    }
}
