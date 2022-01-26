package it.geosolutions.geostore.services.rest.security.oauth2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.log4j.Logger;

import static it.geosolutions.geostore.services.rest.security.oauth2.OAuthUtils.tokenFromParamsOrBearer;

public class IdTokenUsernameProvider implements PreAuthUsernameProvider {

    private Set<String> claimNames=new LinkedHashSet<>();

    private static final Logger LOGGER = Logger.getLogger(IdTokenUsernameProvider.class);

    public static final String ID_TOKEN_PARAM ="id_token";


    public IdTokenUsernameProvider(String... claimNames){
        for (String c:claimNames) this.claimNames.add(c);
    }
    @Override
    public PreAuthUsernameDetails getUsername(HttpServletRequest request, HttpServletResponse response) {
        PreAuthUsernameDetails result=null;
        String idToken= tokenFromParamsOrBearer(ID_TOKEN_PARAM,request);
        if (idToken!=null){
            try {
                PreAuthUsernameDetails details =retrieveUserFromJWT(idToken);
                if (details!=null)
                    result=details;
            } catch (InvalidTokenException e){
                if (LOGGER.isDebugEnabled()){
                    LOGGER.debug("Invalid token id. Will try to authenticate user using the authorization workflow.");
                }
            }
        }
        return result;
    }


    protected PreAuthUsernameDetails retrieveUserFromJWT(String token) {
        DecodedJWT decoded=JWT.decode(token);
        Iterator<String> it=claimNames.iterator();
        PreAuthUsernameDetails details=null;
        String username=null;
        while (it.hasNext() && username==null){
            String name=it.next();
            Claim claim=decoded.getClaim(name);
            if (!claim.isNull()){
                String userClaim=claim.asString();
                 if (!"".equalsIgnoreCase(userClaim)) username=userClaim;
            }
        }
        if (username!=null){
            details=new PreAuthUsernameDetails();
            details.setExtraData(token);
            details.setUsername(username);
            details.setExpired(decoded.getExpiresAt().before(new Date()));
        }
        return details;
    }
}
