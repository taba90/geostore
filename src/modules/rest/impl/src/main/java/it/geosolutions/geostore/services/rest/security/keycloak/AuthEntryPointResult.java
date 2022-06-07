package it.geosolutions.geostore.services.rest.security.keycloak;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthEntryPointResult implements AuthenticationEntryPoint {
    private final Authentication authentication;
    private final AuthChallenge challenge;

    /** Create a FORBIDDEN result. */
    public AuthEntryPointResult() {
        this.authentication = null;
        this.challenge = null;
    }

    /**
     * Create a failed result with a potential challenge to obtain credentials and retry.
     *
     * @param challenge instructions to obtain credentials
     */
    public AuthEntryPointResult(AuthChallenge challenge) {
        this.authentication = null;
        this.challenge = challenge;
    }

    /**
     * Create a successful result.
     *
     * @param authentication valid credentials
     */
    public AuthEntryPointResult(Authentication authentication) {
        Object username = null;
        Object details = null;
        if (authentication.getDetails() instanceof SimpleKeycloakAccount) {
            details = (SimpleKeycloakAccount) authentication.getDetails();

            assert ((SimpleKeycloakAccount) details).getPrincipal() instanceof KeycloakPrincipal;
            final KeycloakPrincipal principal =
                    (KeycloakPrincipal) ((SimpleKeycloakAccount) details).getPrincipal();

            username = principal.getName();

            if (principal.getKeycloakSecurityContext().getIdToken() != null) {
                username =
                        principal.getKeycloakSecurityContext().getIdToken().getPreferredUsername();
            }
        } else {
            username = authentication.getPrincipal();
            details = authentication.getDetails();
        }

        this.authentication =
                new UsernamePasswordAuthenticationToken(
                        username, authentication.getCredentials(), authentication.getAuthorities());
        ((UsernamePasswordAuthenticationToken) this.authentication).setDetails(details);
        this.challenge = null;
    }

    /**
     * Execute the challenge to modify the response. The response should (upon success) contain
     * instructions on how to obtain valid credentials.
     *
     * @param request incoming request
     * @param response response to modify
     * @return does the response contain auth instructions?
     */
    public boolean challenge(HttpServletRequest request, HttpServletResponse response) {
        // if already authenticated, then there is nothing to do so consider this a success
        if (authentication != null) {
            return true;
        }
        // if no challenge exists and no creds are set, then this is FORBIDDEN
        if (challenge == null) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return false;
        }
        // otherwise, defer to the contained challenge
        return challenge.challenge(new SimpleHttpFacade(request, response));
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException, ServletException {
        challenge(request, response);
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public boolean hasAuthentication() {
        return authentication != null;
    }
}
