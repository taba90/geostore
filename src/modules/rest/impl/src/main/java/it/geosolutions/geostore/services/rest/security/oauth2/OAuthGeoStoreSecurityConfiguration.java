package it.geosolutions.geostore.services.rest.security.oauth2;

import com.google.common.collect.ImmutableList;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

import javax.annotation.Resource;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

public abstract class OAuthGeoStoreSecurityConfiguration implements ApplicationContextAware {

    static final String DETAILS_ID="oauth2-client";

    protected ApplicationContext context;


    @Resource
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;

    /**
     * Returns the resource bean containing the Access Token Request info.
     *
     * @return the accessTokenRequest
     */
    public AccessTokenRequest getAccessTokenRequest() {
        return accessTokenRequest;
    }

    /**
     * Set the accessTokenRequest property.
     *
     * @param accessTokenRequest the accessTokenRequest to set
     */
    public void setAccessTokenRequest(AccessTokenRequest accessTokenRequest) {
        this.accessTokenRequest = accessTokenRequest;
    }


    protected OAuth2ProtectedResourceDetails resourceDetails(){
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setId(getDetailsId());

        details.setGrantType("authorization_code");
        details.setAuthenticationScheme(AuthenticationScheme.header);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);

        return details;
    }

    protected String getDetailsId(){return DETAILS_ID;}

    protected OpenIdRestTemplate restTemplate() {
        return new OpenIdRestTemplate(resourceDetails(),new DefaultOAuth2ClientContext(getAccessTokenRequest()),getOAuthAppConfiguration());
    }

    public OpenIdRestTemplate getConfiguredRestTemplate() {

        OpenIdRestTemplate oAuth2RestTemplate = restTemplate();
        setJacksonConverter(oAuth2RestTemplate);
        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider =
                new AuthorizationCodeAccessTokenProvider();
        authorizationCodeAccessTokenProvider.setStateMandatory(false);

        AccessTokenProvider accessTokenProviderChain =
                new AccessTokenProviderChain(
                        Arrays.<AccessTokenProvider>asList(
                                authorizationCodeAccessTokenProvider,
                                new ImplicitAccessTokenProvider(),
                                new ResourceOwnerPasswordAccessTokenProvider(),
                                new ClientCredentialsAccessTokenProvider()));

        oAuth2RestTemplate.setAccessTokenProvider(accessTokenProviderChain);
        return oAuth2RestTemplate;
    }

    private void setJacksonConverter(OAuth2RestTemplate oAuth2RestTemplate){
        List<HttpMessageConverter<?>> converterList=oAuth2RestTemplate.getMessageConverters();
        MappingJackson2HttpMessageConverter jacksonConverter=null;
        for (HttpMessageConverter<?> converter:converterList){
            if (converter instanceof MappingJackson2HttpMessageConverter) {
                jacksonConverter = (MappingJackson2HttpMessageConverter) converter;
                break;
            }
        }
        if (jacksonConverter==null) {
            jacksonConverter = new MappingJackson2HttpMessageConverter();
            oAuth2RestTemplate.getMessageConverters().add(jacksonConverter);
        }
        jacksonConverter.setSupportedMediaTypes(Arrays.asList(new MediaType("application", "json", Charset.forName("UTF-8"))));
    }

    protected OAuth2Configuration getOAuthAppConfiguration(){
        return context.getBean(OAuth2Configuration.class);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.context=applicationContext;
    }
}
