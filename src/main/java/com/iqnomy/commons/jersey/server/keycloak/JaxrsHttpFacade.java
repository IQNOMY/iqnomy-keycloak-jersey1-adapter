package com.iqnomy.commons.jersey.server.keycloak;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

import javax.security.cert.X509Certificate;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.SecurityContext;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.LogoutError;
import org.keycloak.common.util.HostUtils;

import com.sun.jersey.spi.container.ContainerRequest;

public class JaxrsHttpFacade implements OIDCHttpFacade {

	protected final ContainerRequest containerRequest;
	protected final SecurityContext securityContext;
	protected final RequestFacade requestFacade = new RequestFacade();
	protected final ResponseFacade responseFacade = new ResponseFacade();
	protected KeycloakSecurityContext keycloakSecurityContext;
	protected boolean responseFinished;
	protected String error;


	public JaxrsHttpFacade(final ContainerRequest containerRequest, final SecurityContext securityContext) {
		this.containerRequest = containerRequest;
		this.securityContext = securityContext;
	}

	protected class RequestFacade implements OIDCHttpFacade.Request {

		protected String error;

		@Override
		public String getFirstParam(final String param) {
			throw new RuntimeException("NOT IMPLEMENTED");
		}

		@Override
		public String getMethod() {
			return containerRequest.getMethod();
		}

		@Override
		public String getURI() {
			return containerRequest.getRequestUri().toString();
		}

		@Override
		public boolean isSecure() {
			return securityContext.isSecure();
		}

		@Override
		public String getQueryParamValue(final String param) {

			final MultivaluedMap<String, String> queryParams = containerRequest.getQueryParameters();
			if (queryParams == null)
				return null;
			return queryParams.getFirst(param);
		}

		@Override
		public Cookie getCookie(final String cookieName) {
			final Map<String, javax.ws.rs.core.Cookie> cookies = containerRequest.getCookies();
			if (cookies == null)
				return null;
			final javax.ws.rs.core.Cookie cookie = cookies.get(cookieName);
			if (cookie == null)
				return null;
			return new Cookie(cookie.getName(), cookie.getValue(), cookie.getVersion(), cookie.getDomain(),
					cookie.getPath());
		}

		@Override
		public String getHeader(final String name) {
			return containerRequest.getHeaderValue(name);
		}

		@Override
		public List<String> getHeaders(final String name) {
			final MultivaluedMap<String, String> headers = containerRequest.getRequestHeaders();
			return (headers == null) ? null : headers.get(name);
		}

		@Override
		public InputStream getInputStream() {
			return containerRequest.getEntityInputStream();
		}

		@Override
		public String getRemoteAddr() {
			// TODO: implement properly
			return HostUtils.getIpAddress();
		}

		@Override
		public void setError(final AuthenticationError error) {
			this.error = error.toString();
		}

		@Override
		public void setError(final LogoutError error) {
			this.error = error.toString();
		}
	}

	protected class ResponseFacade implements OIDCHttpFacade.Response {

		private final javax.ws.rs.core.Response.ResponseBuilder responseBuilder = javax.ws.rs.core.Response.status(204);

		@Override
		public void setStatus(final int status) {
			responseBuilder.status(status);
		}

		@Override
		public void addHeader(final String name, final String value) {
			responseBuilder.header(name, value);
		}

		@Override
		public void setHeader(final String name, final String value) {
			responseBuilder.header(name, value);
		}

		@Override
		public void resetCookie(final String name, final String path) {
			// For now doesn't need to be supported
			throw new IllegalStateException("Not supported yet");
		}

		@Override
		public void setCookie(final String name, final String value, final String path, final String domain, final int maxAge, final boolean secure,
				final boolean httpOnly) {
			// For now doesn't need to be supported
			throw new IllegalStateException("Not supported yet");
		}

		@Override
		public OutputStream getOutputStream() {
			// For now doesn't need to be supported
			throw new IllegalStateException("Not supported yet");
		}

		@Override
		public void sendError(final int code) {
			final javax.ws.rs.core.Response response = responseBuilder.status(code).entity(requestFacade.error).build();
			throw new WebApplicationException(response);
		}

		@Override
		public void sendError(final int code, final String message) {
			final javax.ws.rs.core.Response response = responseBuilder.status(code).entity(message).build();
			throw new WebApplicationException(response);
		}

		@Override
		public void end() {
			final javax.ws.rs.core.Response response = responseBuilder.build();
			throw new WebApplicationException(response);
		}
	}

	@Override
	public KeycloakSecurityContext getSecurityContext() {
		return keycloakSecurityContext;
	}

	public void setSecurityContext(final KeycloakSecurityContext securityContext) {
		this.keycloakSecurityContext = securityContext;
	}

	@Override
	public Request getRequest() {
		return requestFacade;
	}

	@Override
	public Response getResponse() {
		return responseFacade;
	}

	@Override
	public X509Certificate[] getCertificateChain() {
		throw new IllegalStateException("Not supported yet");
	}

	public boolean isResponseFinished() {
		return responseFinished;
	}

}
