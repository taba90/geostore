package it.geosolutions.geostore.services.rest.security.oauth2;

import it.geosolutions.geostore.core.model.Category;
import it.geosolutions.geostore.services.rest.exception.NotFoundWebEx;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestParam;

import javax.print.attribute.standard.Media;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

public interface OAuthLoginRest {

    @GET
    @Path("/{provider}/login")
    @Secured({ "ROLE_USER", "ROLE_ADMIN", "ROLE_ANONYMOUS" })
    void login(@PathParam("provider") String provider) throws NotFoundWebEx;

    @GET
    @Path("/{provider}/callback")
    @Secured({ "ROLE_USER", "ROLE_ADMIN"})
    Response callback(@PathParam("provider") String provider) throws NotFoundWebEx;

    @POST
    @Path("/{provider}/refresh")
    @Secured({ "ROLE_USER", "ROLE_ADMIN"})
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    Response refresh(@PathParam("provider") String provider, @Multipart("accessTokenDto") InputStream is) throws NotFoundWebEx;

    @GET
    @Path("/{provider}/logout")
    @Secured({ "ROLE_USER", "ROLE_ADMIN"})
    Response logout(@PathParam("provider") String provider) throws NotFoundWebEx;



}
