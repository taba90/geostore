package it.geosolutions.geostore.services.rest.security.oauth2;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import java.util.Date;

public class AccessCookie extends NewCookie {

    private String sameSite;

    public AccessCookie(String name, String value, String sameSite) {
        super(name, value);
        this.sameSite=sameSite;
    }

    public AccessCookie(String name, String value, String path, String domain, String comment, int maxAge, boolean secure,String sameSite) {
        super(name, value, path, domain, comment, maxAge, secure);
        this.sameSite=sameSite;

    }

    public AccessCookie(String name, String value, String path, String domain, String comment, int maxAge, boolean secure, boolean httpOnly,String sameSite) {
        super(name, value, path, domain, comment, maxAge, secure, httpOnly);
        this.sameSite=sameSite;
    }

    public AccessCookie(String name, String value, String path, String domain, int version, String comment, int maxAge, boolean secure,String sameSite) {
        super(name, value, path, domain, version, comment, maxAge, secure);
        this.sameSite=sameSite;
    }

    public AccessCookie(String name, String value, String path, String domain, int version, String comment, int maxAge, Date expiry, boolean secure, boolean httpOnly,String sameSite) {
        super(name, value, path, domain, version, comment, maxAge, expiry, secure, httpOnly);
        this.sameSite=sameSite;
    }

    public AccessCookie(Cookie cookie, String sameSite) {
        super(cookie);
        this.sameSite=sameSite;
    }

    public AccessCookie(Cookie cookie, String comment, int maxAge, boolean secure, String sameSite) {
        super(cookie, comment, maxAge, secure);
        this.sameSite=sameSite;
    }

    public AccessCookie(Cookie cookie, String comment, int maxAge, Date expiry, boolean secure, boolean httpOnly,String sameSite) {
        super(cookie, comment, maxAge, expiry, secure, httpOnly);
        this.sameSite=sameSite;
    }

    @Override
    public String toString() {
        String cookie= super.toString();
        if (sameSite!=null)
            cookie=cookie.concat(";").concat("SameSite=").concat(sameSite);
        return cookie;
    }


}
