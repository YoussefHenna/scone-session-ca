package com.youssefhenna;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class WebApplicationExceptionMapper implements ExceptionMapper<WebApplicationException> {

    record ErrorResponse(String message) {}

    @Override
    public Response toResponse(WebApplicationException e) {
        return Response.status(e.getResponse().getStatus())
            .type(MediaType.APPLICATION_JSON)
            .entity(new ErrorResponse(e.getMessage()))
            .build();
    }
}