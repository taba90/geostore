package it.geosolutions.geostore.services.rest.security.oauth2;

class PreAuthUsernameDetails {

    private String username;

    private boolean expired;

    private Object extraData;

    String getUsername() {
        return username;
    }

    boolean isExpired() {
        return expired;
    }

    Object getExtraData() {
        return extraData;
    }

    void setUsername(String username) {
        this.username = username;
    }

    void setExpired(boolean expired) {
        this.expired = expired;
    }

    void setExtraData(Object extraData) {
        this.extraData = extraData;
    }
}
