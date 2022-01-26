package it.geosolutions.geostore.services.rest.security.oauth2;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

interface PreAuthUsernameProvider {

    PreAuthUsernameDetails getUsername(HttpServletRequest request, HttpServletResponse response);
}
