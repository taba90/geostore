package it.geosolutions.geostore.services.rest;

import it.geosolutions.geostore.services.rest.model.SessionToken;

public interface SessionServiceDelegate {

    public static final String PROVIDER_KEY="PROVIDER";

    SessionToken refresh(String refreshToken, String accessToken);

    void doLogout(String accessToken);
}
