package it.geosolutions.geostore.services.rest.security.oauth2;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.concurrent.TimeUnit;

public class OAuth2Cache {

    private Cache<String, Authentication> cache;

    private int cacheSize = 1000;
    private int cacheExpiration = 30;

    public OAuth2Cache(){
        cache = CacheBuilder.newBuilder()
                .maximumSize(cacheSize)
                .expireAfterWrite(cacheExpiration, TimeUnit.MINUTES)
                .build();
    }

    public Authentication get(String accessToken){
        return cache.asMap().get(accessToken);
    }

    public Authentication putCacheEntry(String accessToken, Authentication authentication){
        // make sure we preserve the refresh token if present in old entry
        Authentication old=get(accessToken);
        TokenDetails oldDetails=OAuthUtils.getTokenDetails(old);
        if (oldDetails!=null) {
            TokenDetails newDetails = OAuthUtils.getTokenDetails(authentication);
            OAuth2AccessToken newToken = newDetails.getAccessToken();
            OAuth2AccessToken oldToken = oldDetails.getAccessToken();
            if (newToken.getRefreshToken() == null && oldToken != null) {
                DefaultOAuth2AccessToken defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(newToken.getValue());
                defaultOAuth2AccessToken.setRefreshToken(oldToken.getRefreshToken());
                newDetails.setAccessToken(defaultOAuth2AccessToken);
            }
        }

        this.cache.put(accessToken,authentication);
        return authentication;
    }

    public void removeEntry(String accessToken){
        this.cache.invalidate(accessToken);
    }

    public void clear(){
        cache.invalidateAll();
    }
}
