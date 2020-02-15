package org.eclipse.milo.opcua.stack.server;

import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.serialization.EncodingLimits;
import org.eclipse.milo.opcua.stack.core.serialization.SerializationContext;
import org.eclipse.milo.opcua.stack.core.types.DataTypeManager;
import org.eclipse.milo.opcua.stack.core.types.DefaultDataTypeManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.DiagnosticInfo;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.eclipse.milo.opcua.stack.core.util.EndpointUtil;
import org.eclipse.milo.opcua.stack.server.services.LocalDiscoveryServiceSet;
import org.eclipse.milo.opcua.stack.server.services.ServiceRequest;
import org.eclipse.milo.opcua.stack.server.transport.ServerChannelManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.base.Strings.nullToEmpty;
import static com.google.common.collect.Lists.newArrayList;
import static java.util.stream.Collectors.toList;
import static org.eclipse.milo.opcua.stack.core.util.ConversionUtil.a;

public class UaStackLdsServer extends UaStackServer {
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final DataTypeManager dataTypeManager = new DefaultDataTypeManager();
	private final NamespaceTable namespaceTable = new NamespaceTable();
	private final ServerChannelManager channelManager;
	private final SerializationContext serializationContext;
	private final UaStackServerConfig config;

	public UaStackLdsServer(UaStackServerConfig config) {
		super(config);
		this.config = config;
		channelManager = new ServerChannelManager(this);

		serializationContext = new SerializationContext() {
			@Override
			public EncodingLimits getEncodingLimits() {
				return config.getEncodingLimits();
			}

			@Override
			public NamespaceTable getNamespaceTable() {
				return namespaceTable;
			}

			@Override
			public DataTypeManager getDataTypeManager() {
				return dataTypeManager;
			}
		};

		config.getEndpoints().forEach(endpoint -> {
			String path = EndpointUtil.getPath(endpoint.getEndpointUrl());
			this.addServiceSet(path, new DiscoveryServiceSet());
		});
	}


	public void addServiceSet(String path, DiscoveryServiceSet serviceSet) {

		addServiceHandler(path, GetEndpointsRequest.class, serviceSet::onGetEndpoints);
		addServiceHandler(path, FindServersRequest.class, serviceSet::onFindServers);
		addServiceHandler(path, RegisterServer2Request.class, serviceSet::onRegister2Server);
		addServiceHandler(path, RegisterServerRequest.class, serviceSet::onRegisterServer);
	}


	private class DiscoveryServiceSet implements LocalDiscoveryServiceSet {
		private final LinkedList<RegisteredServer> registeredServers;
		private final HashMap<RegisteredServer, Date> registeredServerLastSeen;
		private Consumer<RegisteredServer> registerServerConsumer = null;

		private DiscoveryServiceSet() {
			registeredServers = new LinkedList<>();
			registeredServerLastSeen = new HashMap<>();
		}

		@Override
		public void onGetEndpoints(ServiceRequest serviceRequest) {
			GetEndpointsRequest request = (GetEndpointsRequest) serviceRequest.getRequest();

			List<String> profileUris = request.getProfileUris() != null ?
					newArrayList(request.getProfileUris()) :
					new ArrayList<>();

			List<EndpointDescription> allEndpoints = getEndpointDescriptions()
					.stream()
					.filter(ed -> !ed.getEndpointUrl().endsWith("/discovery"))
					.filter(ed -> filterProfileUris(ed, profileUris))
					.collect(toList());

			List<EndpointDescription> matchingEndpoints = allEndpoints.stream()
					.filter(endpoint -> filterEndpointUrls(endpoint, request.getEndpointUrl()))
					.map(endpoint ->
							replaceApplicationDescription(
									endpoint,
									getFilteredApplicationDescription(request.getEndpointUrl())
							)
					)
					.collect(toList());

			GetEndpointsResponse response = new GetEndpointsResponse(
					serviceRequest.createResponseHeader(),
					matchingEndpoints.isEmpty() ?
							a(allEndpoints, EndpointDescription.class) :
							a(matchingEndpoints, EndpointDescription.class)
			);

			serviceRequest.setResponse(response);

		}

		private boolean filterProfileUris(EndpointDescription endpoint, List<String> profileUris) {
			return profileUris.size() == 0 || profileUris.contains(endpoint.getTransportProfileUri());
		}

		private boolean filterEndpointUrls(EndpointDescription endpoint, String endpointUrl) {
			try {
				String requestedHost = EndpointUtil.getHost(endpointUrl);
				String endpointHost = EndpointUtil.getHost(endpoint.getEndpointUrl());

				return nullToEmpty(requestedHost).equalsIgnoreCase(endpointHost);
			} catch (Throwable e) {
				logger.debug("Unable to create URI.", e);
				return false;
			}
		}

		private EndpointDescription replaceApplicationDescription(
				EndpointDescription endpoint,
				ApplicationDescription applicationDescription) {

			return new EndpointDescription(
					endpoint.getEndpointUrl(),
					applicationDescription,
					endpoint.getServerCertificate(),
					endpoint.getSecurityMode(),
					endpoint.getSecurityPolicyUri(),
					endpoint.getUserIdentityTokens(),
					endpoint.getTransportProfileUri(),
					endpoint.getSecurityLevel()
			);
		}

		private ApplicationDescription getApplicationDescriptionFromRegisteredServer(
				RegisteredServer registeredServer, String[] localeIds) {
			LocalizedText serverName = null;
			if (localeIds != null && localeIds.length > 0 && registeredServer.getServerNames() != null) {
				List<String> locales = Arrays.asList(localeIds);
				List<LocalizedText> names = Arrays.asList(registeredServer.getServerNames());
				Optional<LocalizedText> found = names.stream().filter(n -> locales.contains(n.getLocale())).findFirst();
				if (found.isPresent()) {
					serverName = found.get();
				}
			}
			if (serverName == null) {
				// client does not want to filter or filtered locale not found
				// we can select the most suitable on our own
				if (registeredServer.getServerNames() != null) {
					serverName = registeredServer.getServerNames()[0];
				} else {
					serverName = new LocalizedText("en", "undefined");
				}
			}

			return new ApplicationDescription(
					registeredServer.getServerUri(),
					registeredServer.getProductUri(),
					serverName,
					registeredServer.getServerType(),
					registeredServer.getGatewayServerUri(),
					null,
					registeredServer.getDiscoveryUrls()
			);
		}

		@Override
		public void onFindServers(ServiceRequest serviceRequest){
			FindServersRequest request = (FindServersRequest) serviceRequest.getRequest();

			//ApplicationDescription selfAppDescription = getApplicationDescription(serviceRequest,request.getEndpointUrl());
			String[] discoveryUrls = new String[1];
			discoveryUrls[0] = request.getEndpointUrl();

			// create current server ApplicationDescription : LDS
			ApplicationDescription selfAppDescription = new ApplicationDescription(
					config.getApplicationUri(),
					config.getProductUri(),
					config.getApplicationName(),
					ApplicationType.Server,
					null,
					null,
					discoveryUrls

			);

			// create a list of all available ApplicationDescription
			LinkedList<ApplicationDescription> applicationDescriptions = new LinkedList<>();

			// add default application description : LDS
			applicationDescriptions.add(selfAppDescription);

			// for each servers in registeredServers add their discovery URL to ApplicationDescription
			applicationDescriptions.addAll(
					this.getRegisteredServers().stream().map(
							r -> getApplicationDescriptionFromRegisteredServer(r, request.getLocaleIds())
					).collect( Collectors.toList() ));

			// return a suitable response of type FindServers
			FindServersResponse response = new FindServersResponse(
					serviceRequest.createResponseHeader(),
					a(applicationDescriptions, ApplicationDescription.class)
			);

			serviceRequest.setResponse(response);

		}

		private ApplicationDescription getFilteredApplicationDescription(String endpointUrl) {
			List<String> allDiscoveryUrls = config.getEndpoints()
					.stream()
					.map(EndpointConfiguration::getEndpointUrl)
					.filter(url -> url.endsWith("/discovery"))
					.collect(Collectors.toList());

			if (allDiscoveryUrls.isEmpty()) {
				allDiscoveryUrls = config.getEndpoints()
						.stream()
						.map(EndpointConfiguration::getEndpointUrl)
						.collect(Collectors.toList());
			}

			List<String> matchingDiscoveryUrls = allDiscoveryUrls.stream()
					.filter(discoveryUrl -> {
						try {

							String requestedHost = EndpointUtil.getHost(endpointUrl);
							String discoveryHost = EndpointUtil.getHost(discoveryUrl);

							logger.debug("requestedHost={}, discoveryHost={}", requestedHost, discoveryHost);

							return nullToEmpty(requestedHost).equalsIgnoreCase(discoveryHost);
						} catch (Throwable e) {
							logger.debug("Unable to create URI.", e);
							return false;
						}
					})
					.collect(toList());


			logger.debug("Matching discovery URLs: {}", matchingDiscoveryUrls);

			return new ApplicationDescription(
					config.getApplicationUri(),
					config.getProductUri(),
					config.getApplicationName(),
					ApplicationType.Server,
					null,
					null,
					matchingDiscoveryUrls.isEmpty() ?
							a(allDiscoveryUrls, String.class) :
							a(matchingDiscoveryUrls, String.class)
			);
		}


		private StatusCode processRegisterServer(RegisteredServer requestServer) {


			// check if server already in list
			RegisteredServer registeredServer = null;


			Optional<RegisteredServer> rs =
					registeredServers.stream().filter(s -> s.getServerUri().compareTo(requestServer.getServerUri()) == 0)
							.findFirst();
			if (rs.isPresent()) {
				registeredServer = rs.get();
			}

			// check semaphore
			if (requestServer.getSemaphoreFilePath() != null && requestServer.getSemaphoreFilePath().length() > 0) {
				if (!new File(requestServer.getSemaphoreFilePath()).isFile()) {
					return new StatusCode(StatusCodes.Bad_SempahoreFileMissing);
				}
			}

			// Todo : multicast enabled ...

			if (!requestServer.getIsOnline()) {

				// server shutting down, unregister it
				if (registeredServer == null) {
					logger.warn("Could not unregister server " + requestServer.getServerUri() + ". Not registered");
					return new StatusCode(StatusCodes.Bad_NotFound);
				}

				if (registerServerConsumer != null) {
					registerServerConsumer.accept(registeredServer);
				}

				this.registeredServers.remove(registeredServer);
				this.registeredServerLastSeen.remove(registeredServer);

				return StatusCode.GOOD;
			}

			if (registeredServer == null) {
				// this server did not yet register, create new

				LoggerFactory.getLogger(UaStackLdsServer.class)
						.info("RegisterServer called by new server: {}" , requestServer.getServerUri());

				registeredServer = requestServer;
				this.registeredServers.add(registeredServer);
				if (registerServerConsumer != null) {
					registerServerConsumer.accept(registeredServer);
					registerServerConsumer.accept(registeredServer);
				}
			}

			// update or add last seen value
			this.registeredServerLastSeen.put(registeredServer, new Date());
			return StatusCode.GOOD;
		}

		@Override
		public void onRegisterServer(ServiceRequest serviceRequest) throws UaException {
			// Create Register Method Here
			LoggerFactory.getLogger(UaStackLdsServer.class).info("-----> method onRegisterServer has been called .");

			// fetch the registered server discovery URLs
			RegisteredServer requesterServer = ((RegisterServer2Request) serviceRequest.getRequest()).getServer();

			// create a register2 response handlerArrayList<StatusCode> configurationResults = new ArrayList<>();
			ArrayList<StatusCode> configurationResults = new ArrayList<>();
			ArrayList<DiagnosticInfo> diagnosticInfos = new ArrayList<>();

			ResponseHeader header =
					serviceRequest.createResponseHeader(
							processRegisterServer(requesterServer));
			serviceRequest.setResponse(new RegisterServer2Response(
					header,
					configurationResults.toArray(new StatusCode[0]),
					diagnosticInfos.toArray(new DiagnosticInfo[0])
			));
		}

		@Override
		public void onRegister2Server(ServiceRequest serviceRequest) throws UaException {
			LoggerFactory.getLogger(UaStackLdsServer.class).info("-----> method onRegister2Server has been called .");

			// fetch the registered server discovery URLs
			RegisteredServer requesterServer = ((RegisterServer2Request) serviceRequest.getRequest()).getServer();

			// create a register2 response handlerArrayList<StatusCode> configurationResults = new ArrayList<>();
			ArrayList<StatusCode> configurationResults = new ArrayList<>();
			ArrayList<DiagnosticInfo> diagnosticInfos = new ArrayList<>();

			ResponseHeader header =
					serviceRequest.createResponseHeader(
							processRegisterServer(requesterServer));
			serviceRequest.setResponse(new RegisterServer2Response(
					header,
					configurationResults.toArray(new StatusCode[0]),
					diagnosticInfos.toArray(new DiagnosticInfo[0])
			));

		}

		protected List<RegisteredServer> getRegisteredServers() {
			return this.registeredServers;
		}

	}



}
