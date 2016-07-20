package com.iqnomy.commons.jersey.server.keycloak;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.BasicAuthRequestAuthenticator;
import org.keycloak.adapters.BearerTokenRequestAuthenticator;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.NodesRegistrationManagement;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.common.constants.GenericConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jersey.spi.container.ContainerRequest;
import com.sun.jersey.spi.container.ContainerRequestFilter;
import com.sun.jersey.spi.container.ContainerResponseFilter;
import com.sun.jersey.spi.container.ResourceFilter;

public class JerseyBearerTokenFilterImpl implements ResourceFilter, ContainerRequestFilter {

	private final static Logger log = LoggerFactory.getLogger(JerseyBearerTokenFilterImpl.class);

	private static final Map<Class<? extends KeycloakConfigResolver>, AdapterDeploymentContext> configResolverClassDeploymentContexts = new HashMap<>();
	private static final Map<String, AdapterDeploymentContext> configFileDeploymentContexts = new HashMap<>();
	private final String keycloakConfigFile;
	private final Class<? extends KeycloakConfigResolver> keycloakConfigResolverClass;
	protected volatile boolean started;


	protected AdapterDeploymentContext deploymentContext;

	// TODO: Should also somehow handle stop lifecycle for de-registration
	protected NodesRegistrationManagement nodesRegistrationManagement;
	protected UserSessionManagement userSessionManagement = new EmptyUserSessionManagement();

	@Override
	public ContainerRequestFilter getRequestFilter() {
		return this;
	}

	@Override
	public ContainerResponseFilter getResponseFilter() {
		return null;
	}

	@Override
	public ContainerRequest filter(final ContainerRequest request) {
		try {
			final SecurityContext securityContext = getRequestSecurityContext(request);
			final JaxrsHttpFacade facade = new JaxrsHttpFacade(request, securityContext);
			if (handlePreauth(facade)) {
				return request;
			}

			final KeycloakDeployment resolvedDeployment = deploymentContext.resolveDeployment(facade);

			nodesRegistrationManagement.tryRegister(resolvedDeployment);

			bearerAuthentication(facade, request, resolvedDeployment);
			return request;
		} catch (final WebApplicationException e) {
			throw e;
		} catch (final Throwable e) {
			throw new WebApplicationException(e);
		}
	}

	public JerseyBearerTokenFilterImpl(final Class<? extends KeycloakConfigResolver> keycloakConfigResolverClass) {
		this(keycloakConfigResolverClass, null);
	}

	public JerseyBearerTokenFilterImpl(final String keycloakConfigFile) {
		this(null, keycloakConfigFile);
	}

	private JerseyBearerTokenFilterImpl(final Class<? extends KeycloakConfigResolver> keycloakConfigResolverClass, final String keycloakConfigFile) {
		this.keycloakConfigResolverClass = keycloakConfigResolverClass;
		this.keycloakConfigFile = keycloakConfigFile;
		attemptStart();
	}

	// INITIALIZATION AND STARTUP

	protected void attemptStart() {
		if (started) {
			throw new IllegalStateException("Filter already started. Make sure to specify just keycloakConfigResolver or keycloakConfigFile but not both");
		}

		if (isInitialized()) {
			start();
		} else {
			log.debug("Not yet initialized");
		}
	}

	protected boolean isInitialized() {
		return this.keycloakConfigFile != null || this.keycloakConfigResolverClass != null;
	}

	protected void start() {
		if (started) {
			throw new IllegalStateException("Filter already started. Make sure to specify just keycloakConfigResolver or keycloakConfigFile but not both");
		}

		if (keycloakConfigResolverClass != null) {
			deploymentContext = configResolverClassDeploymentContexts.get(keycloakConfigResolverClass);
			if (null == deploymentContext) {
				try {
					final KeycloakConfigResolver resolver = keycloakConfigResolverClass.newInstance();
					log.info("Using " + resolver + " to resolve Keycloak configuration on a per-request basis.");
					deploymentContext = new AdapterDeploymentContext(resolver);
					configResolverClassDeploymentContexts.put(keycloakConfigResolverClass, deploymentContext);
				} catch (final Exception e) {
					throw new RuntimeException("Unable to instantiate resolver " + keycloakConfigResolverClass.getName());
				}
			}
		} else {
			if (keycloakConfigFile == null) {
				throw new IllegalArgumentException("You need to specify either keycloakConfigResolverClass or keycloakConfigFile in configuration");
			}
			deploymentContext = configFileDeploymentContexts.get(keycloakConfigFile);
			if (null == deploymentContext) {
				final InputStream is = loadKeycloakConfigFile();
				final KeycloakDeployment kd = KeycloakDeploymentBuilder.build(is);
				deploymentContext = new AdapterDeploymentContext(kd);
				configFileDeploymentContexts.put(keycloakConfigFile, this.deploymentContext);
				log.info("Keycloak is using a per-deployment configuration loaded from: " + keycloakConfigFile);
			}
		}

		nodesRegistrationManagement = new NodesRegistrationManagement();
		started = true;
	}

	protected InputStream loadKeycloakConfigFile() {
		if (keycloakConfigFile.startsWith(GenericConstants.PROTOCOL_CLASSPATH)) {
			final String classPathLocation = keycloakConfigFile.replace(GenericConstants.PROTOCOL_CLASSPATH, "");
			log.debug("Loading config from classpath on location: " + classPathLocation);
			// Try current class classloader first
			InputStream is = getClass().getClassLoader().getResourceAsStream(classPathLocation);
			if (is == null) {
				is = Thread.currentThread().getContextClassLoader().getResourceAsStream(classPathLocation);
			}

			if (is != null) {
				return is;
			} else {
				throw new RuntimeException("Unable to find config from classpath: " + keycloakConfigFile);
			}
		} else {
			// Fallback to file
			try {
				log.debug("Loading config from file: " + keycloakConfigFile);
				return new FileInputStream(keycloakConfigFile);
			} catch (final FileNotFoundException fnfe) {
				log.error("Config not found on " + keycloakConfigFile);
				throw new RuntimeException(fnfe);
			}
		}
	}

	protected boolean handlePreauth(final JaxrsHttpFacade facade) {
		final PreAuthActionsHandler handler = new PreAuthActionsHandler(userSessionManagement, deploymentContext, facade);
		if (handler.handleRequest()) {
			// Send response now (if not already sent)
			if (!facade.isResponseFinished()) {
				facade.getResponse().end();
			}
			return true;
		}

		return false;
	}

	protected void bearerAuthentication(final JaxrsHttpFacade facade, final ContainerRequest request, final KeycloakDeployment resolvedDeployment) {
		BearerTokenRequestAuthenticator authenticator = new BearerTokenRequestAuthenticator(resolvedDeployment);
		AuthOutcome outcome = authenticator.authenticate(facade);

		if (outcome == AuthOutcome.NOT_ATTEMPTED && resolvedDeployment.isEnableBasicAuth()) {
			authenticator = new BasicAuthRequestAuthenticator(resolvedDeployment);
			outcome = authenticator.authenticate(facade);
		}

		if (outcome == AuthOutcome.FAILED || outcome == AuthOutcome.NOT_ATTEMPTED) {
			final AuthChallenge challenge = authenticator.getChallenge();
			log.debug("Authentication outcome: " + outcome);
			final boolean challengeSent = challenge.challenge(facade);
			if (!challengeSent) {
				// Use some default status code
				facade.getResponse().setStatus(Response.Status.UNAUTHORIZED.getStatusCode());
			}

			// Send response now (if not already sent)
			if (!facade.isResponseFinished()) {
				facade.getResponse().end();
			}
			return;
		} else {
			if (verifySslFailed(facade, resolvedDeployment)) {
				return;
			}
		}

		propagateSecurityContext(facade, request, resolvedDeployment, authenticator);
		handleAuthActions(facade, resolvedDeployment);
	}

	protected void propagateSecurityContext(final JaxrsHttpFacade facade, final ContainerRequest request, final KeycloakDeployment resolvedDeployment, final BearerTokenRequestAuthenticator bearer) {
		final RefreshableKeycloakSecurityContext skSession = new RefreshableKeycloakSecurityContext(resolvedDeployment, null, bearer.getTokenString(), bearer.getToken(), null, null, null);

		// Not needed to do resteasy specifics as KeycloakSecurityContext can be always retrieved from SecurityContext by typecast SecurityContext.getUserPrincipal to KeycloakPrincipal
		// ResteasyProviderFactory.pushContext(KeycloakSecurityContext.class, skSession);

		facade.setSecurityContext(skSession);
		final String principalName = AdapterUtils.getPrincipalName(resolvedDeployment, bearer.getToken());
		final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<RefreshableKeycloakSecurityContext>(principalName, skSession);
		final SecurityContext anonymousSecurityContext = getRequestSecurityContext(request);
		final boolean isSecure = anonymousSecurityContext.isSecure();
		final Set<String> roles = AdapterUtils.getRolesFromSecurityContext(skSession);

		final SecurityContext ctx = new SecurityContext() {
			@Override
			public Principal getUserPrincipal() {
				return principal;
			}

			@Override
			public boolean isUserInRole(final String role) {
				return roles.contains(role);
			}

			@Override
			public boolean isSecure() {
				return isSecure;
			}

			@Override
			public String getAuthenticationScheme() {
				return "OAUTH_BEARER";
			}
		};
		request.setSecurityContext(ctx);
	}

	protected boolean verifySslFailed(final JaxrsHttpFacade facade, final KeycloakDeployment deployment) {
		if (!facade.getRequest().isSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
			log.warn("SSL is required to authenticate, but request is not secured");
			facade.getResponse().sendError(403, "SSL required!");
			return true;
		}
		return false;
	}

	protected SecurityContext getRequestSecurityContext(final ContainerRequest request) {
		return request.getSecurityContext();
	}

	protected void handleAuthActions(final JaxrsHttpFacade facade, final KeycloakDeployment deployment) {
		final AuthenticatedActionsHandler authActionsHandler = new AuthenticatedActionsHandler(deployment, facade);
		if (authActionsHandler.handledRequest()) {
			// Send response now (if not already sent)
			if (!facade.isResponseFinished()) {
				facade.getResponse().end();
			}
		}
	}

	// We don't have any sessions to manage with pure jaxrs filter
	private static class EmptyUserSessionManagement implements UserSessionManagement {

		@Override
		public void logoutAll() {
		}

		@Override
		public void logoutHttpSessions(final List<String> ids) {
		}
	}

}