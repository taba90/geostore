package it.geosolutions.geostore.services.rest.security.oauth2;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.concurrent.TimeUnit;

/**
 * A cache for OAuth2 Authentication object. Authentication instances are identified by the
 * corresponding accessToken.
 */
public class OAuth2Cache {

    private Cache<String, Authentication> cache;

    private int cacheSize = 1000;
    private int cacheExpiration = 30;

    public OAuth2Cache() {
        cache = CacheBuilder.newBuilder()
                .maximumSize(cacheSize)
                .expireAfterWrite(cacheExpiration, TimeUnit.MINUTES)
                .build();
    }

    /**
     * Retrieve the authentication by its accessToken value.
     *
     * @param accessToken the accessToken.
     * @return the Authentication identified by the token if present. Null otherwise.
     */
    public Authentication get(String accessToken) {
        return cache.asMap().get(accessToken);
    }

    /**
     * Put an Authentication instance identified by an accessToken value.
     * If the passed Authentication instance those not have a refresh token
     * and we have an old one that has, the refresh Token
     * is set to the new instance.
     *
     * @param accessToken    the access token identifying the instance to update
     * @param authentication the Authentication to cache.
     * @return the Authentication cached.
     */
    public Authentication putCacheEntry(String accessToken, Authentication authentication) {
        Authentication old = get(accessToken);
        TokenDetails oldDetails = OAuthUtils.getTokenDetails(old);
        if (oldDetails != null) {
            TokenDetails newDetails = OAuthUtils.getTokenDetails(authentication);
            OAuth2AccessToken newToken = newDetails.getAccessToken();
            OAuth2AccessToken oldToken = oldDetails.getAccessToken();
            if (newToken.getRefreshToken() == null && oldToken != null) {
                DefaultOAuth2AccessToken defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(newToken.getValue());
                defaultOAuth2AccessToken.setRefreshToken(oldToken.getRefreshToken());
                newDetails.setAccessToken(defaultOAuth2AccessToken);
            }
        }

        this.cache.put(accessToken, authentication);
        return authentication;
    }

    /**
     * Remove an authentication from the cache.
     *
     * @param accessToken the accessToken identifying the authentication to remove.
     */
    public void removeEntry(String accessToken) {
        this.cache.invalidate(accessToken);
    }

}
