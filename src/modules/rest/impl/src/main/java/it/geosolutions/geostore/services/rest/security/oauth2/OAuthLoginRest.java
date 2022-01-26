package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.model.Category;
import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.springframework.security.access.annotation.Secured;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public interface OAuthLoginRest {

    @GET
    @Path("/{provider}/login")
    @Secured({ "ROLE_USER", "ROLE_ADMIN", "ROLE_ANONYMOUS" })
    void login(@PathParam("provider") String provider) throws NotFoundWebEx;

    @GET
    @Path("/{provider}/callback")
    @Secured({ "ROLE_USER", "ROLE_ADMIN"})
    Response callback(@PathParam("provider") String provider) throws NotFoundWebEx;
}
