/*
 * Copyright (c) 2019 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.server;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.common.eventbus.EventBus;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.api.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.core.ServerTable;
import org.eclipse.milo.opcua.sdk.server.api.AddressSpaceManager;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.model.nodes.objects.ObjectTypeManagerInitializer;
import org.eclipse.milo.opcua.sdk.server.model.nodes.variables.VariableTypeManagerInitializer;
import org.eclipse.milo.opcua.sdk.server.namespaces.OpcUaNamespace;
import org.eclipse.milo.opcua.sdk.server.namespaces.ServerNamespace;
import org.eclipse.milo.opcua.sdk.server.nodes.factories.EventFactory;
import org.eclipse.milo.opcua.sdk.server.services.helpers.BrowseHelper.BrowseContinuationPoint;
import org.eclipse.milo.opcua.sdk.server.subscriptions.Subscription;
import org.eclipse.milo.opcua.stack.client.DiscoveryClient;
import org.eclipse.milo.opcua.stack.core.*;
import org.eclipse.milo.opcua.stack.core.Stack;
import org.eclipse.milo.opcua.stack.core.serialization.SerializationContext;
import org.eclipse.milo.opcua.stack.core.types.DataTypeManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.eclipse.milo.opcua.stack.core.util.EndpointUtil;
import org.eclipse.milo.opcua.stack.core.util.ManifestUtil;
import org.eclipse.milo.opcua.stack.server.UaStackLdsServer;
import org.eclipse.milo.opcua.stack.server.UaStackServer;
import org.eclipse.milo.opcua.stack.server.services.AttributeHistoryServiceSet;
import org.eclipse.milo.opcua.stack.server.services.AttributeServiceSet;
import org.eclipse.milo.opcua.stack.server.services.MethodServiceSet;
import org.eclipse.milo.opcua.stack.server.services.MonitoredItemServiceSet;
import org.eclipse.milo.opcua.stack.server.services.NodeManagementServiceSet;
import org.eclipse.milo.opcua.stack.server.services.SessionServiceSet;
import org.eclipse.milo.opcua.stack.server.services.SubscriptionServiceSet;
import org.eclipse.milo.opcua.stack.server.services.ViewServiceSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

public class OpcUaServer {

    public static final String SDK_VERSION =
        ManifestUtil.read("X-SDK-Version").orElse("dev");

    static {
        Logger logger = LoggerFactory.getLogger(OpcUaServer.class);
        logger.info("Eclipse Milo OPC UA Stack version: {}", Stack.VERSION);
        logger.info("Eclipse Milo OPC UA Server SDK version: {}", SDK_VERSION);
    }

    private static final ScheduledExecutorService SCHEDULED_EXECUTOR_SERVICE = Stack.sharedScheduledExecutor();

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Map<ByteString, BrowseContinuationPoint> browseContinuationPoints = Maps.newConcurrentMap();

    private final Map<NodeId, ReferenceType> referenceTypes = Maps.newConcurrentMap();

    private final Map<UInteger, Subscription> subscriptions = Maps.newConcurrentMap();

    private final ServerTable serverTable = new ServerTable();
    AtomicLong requestHandle = new AtomicLong(1L);

    private final AddressSpaceManager addressSpaceManager = new AddressSpaceManager(this);
    private final SessionManager sessionManager = new SessionManager(this);
    private final ObjectTypeManager objectTypeManager = new ObjectTypeManager();
    private final VariableTypeManager variableTypeManager = new VariableTypeManager();
    private final EventBus eventBus = new EventBus("server");
    private final EventFactory eventFactory = new EventFactory(this);
    private final UaStackServer stackServer;
    private final OpcUaNamespace opcUaNamespace;
    private final ServerNamespace serverNamespace;
    private final OpcUaServerConfig config;

    public OpcUaServer(OpcUaServerConfig config) {
        this(config, false);
    }

    public OpcUaServer(OpcUaServerConfig config, boolean isLdsServer) {
        this.config = config;

        if( isLdsServer){
            stackServer = new UaStackLdsServer(this.config);
        }else{
            stackServer = new UaStackServer(this.config);
        }

        Stream<String> paths = stackServer.getConfig().getEndpoints()
            .stream()
            .map(e -> EndpointUtil.getPath(e.getEndpointUrl()))
            .distinct();

        paths.filter(path -> !path.endsWith("/discovery")).forEach(path -> {
            stackServer.addServiceSet(path, (AttributeServiceSet) sessionManager);
            stackServer.addServiceSet(path, (AttributeHistoryServiceSet) sessionManager);
            stackServer.addServiceSet(path, (MethodServiceSet) sessionManager);
            stackServer.addServiceSet(path, (MonitoredItemServiceSet) sessionManager);
            stackServer.addServiceSet(path, (NodeManagementServiceSet) sessionManager);
            stackServer.addServiceSet(path, (SessionServiceSet) sessionManager);
            stackServer.addServiceSet(path, (SubscriptionServiceSet) sessionManager);
            stackServer.addServiceSet(path, (ViewServiceSet) sessionManager);
        });

        ObjectTypeManagerInitializer.initialize(stackServer.getNamespaceTable(), objectTypeManager);

        VariableTypeManagerInitializer.initialize(variableTypeManager);

        opcUaNamespace = new OpcUaNamespace(this);
        opcUaNamespace.startup();

        serverNamespace = new ServerNamespace(this);
        serverNamespace.startup();

        serverTable.addUri(stackServer.getConfig().getApplicationUri());

        for (ReferenceType referenceType : BuiltinReferenceType.values()) {
            referenceTypes.put(referenceType.getNodeId(), referenceType);
        }
    }

    public OpcUaServerConfig getConfig() {
        return config;
    }

    public CompletableFuture<OpcUaServer> startup() {
        eventFactory.startup();

        return stackServer.startup()
            .thenApply(s -> OpcUaServer.this);
    }

    public CompletableFuture<OpcUaServer> shutdown() {
        eventFactory.shutdown();

        subscriptions.values()
            .forEach(Subscription::deleteSubscription);

        return stackServer.shutdown()
            .thenApply(s -> OpcUaServer.this);
    }

    public CompletableFuture<StatusCode> registerWithDiscoveryServer(String discoveryServerUrl) throws Exception {

        List<EndpointDescription> endpoints;

        endpoints = DiscoveryClient.getEndpoints(discoveryServerUrl).get();


        EndpointDescription endpoint = endpoints.stream()
                .findFirst()
                .orElseThrow(() -> new Exception("no desired endpoints returned"));

        OpcUaClientConfig registerClientConfig = OpcUaClientConfig.builder()
                .setApplicationName(LocalizedText.english("Client To Send Server Request"))
                .setApplicationUri("urn:eclipse:milo:examples:client")
                .setEndpoint(endpoint)
                .setIdentityProvider(new AnonymousProvider())
                .build();

        OpcUaClient registerClient = OpcUaClient.create(registerClientConfig);

        RequestHeader header = new RequestHeader(
                null,
                DateTime.now(),
                uint(requestHandle.getAndIncrement()),
                uint(0),
                null,
                uint(60),
                null
        );

        LocalizedText[] serverNames = new LocalizedText[1];
        serverNames[0] = this.config.getApplicationName();

        List<String> discoveryUrlsList = new ArrayList<>();
        stackServer.getEndpointDescriptions().stream()
                .filter(e -> e.getEndpointUrl().endsWith("/discovery"))
                .forEach(e -> {
                    discoveryUrlsList.add(e.getEndpointUrl());
                });


        String[] discoveryUrlsArray = new String[discoveryUrlsList.size()];
        discoveryUrlsArray = discoveryUrlsList.toArray(discoveryUrlsArray);


        RegisteredServer serverToBeRegistered = new RegisteredServer(
                this.config.getApplicationUri(),
                this.config.getProductUri(),
                serverNames,
                ApplicationType.ClientAndServer,
                null,
                discoveryUrlsArray,
                null,
                true
        );

        RegisterServer2Request registerServer2Request = new RegisterServer2Request(
                header,
                serverToBeRegistered,
                null
        );

        CompletableFuture<StatusCode> futureRegisterResult = new CompletableFuture<StatusCode>();

        // first try RegisterServer2
        registerClient.connect().get();
        CompletableFuture<RegisterServer2Response> future2 = registerClient.sendRequest(registerServer2Request);
        future2.whenComplete((response2, ex2) -> {

            if (response2 == null) {
                logger.error("RegisterServer2 failed with error: {}", ex2.getMessage(), ex2);
            } else if (response2.getResponseHeader().getServiceResult().getValue() == StatusCodes.Bad_NotImplemented ||
                    response2.getResponseHeader().getServiceResult().getValue() ==
                            StatusCodes.Bad_ServiceUnsupported) {
                // RegisterServer2 failed, try RegisterServer
                RegisterServerRequest registerServerRequest = new RegisterServerRequest(header, serverToBeRegistered);
                CompletableFuture<RegisterServerResponse> future = registerClient.sendRequest(registerServerRequest);
                future.whenComplete((response, ex) -> {
                    if (response == null) {
                        logger.error("RegisterServer failed with error: {}", ex.getMessage(), ex);
                        futureRegisterResult.complete(new StatusCode(StatusCodes.Bad_UnexpectedError));
                    } else if (response.getResponseHeader().getServiceResult().isBad()) {
                        logger.error("RegisterServer failed with status code: {}",
                                response.getResponseHeader().getServiceResult());
                        futureRegisterResult.complete(response.getResponseHeader().getServiceResult());
                    } else {
                        futureRegisterResult.complete(response.getResponseHeader().getServiceResult());
                    }
                });
            } else {

                futureRegisterResult.complete(response2.getResponseHeader().getServiceResult());
            }
        });

        return futureRegisterResult;
    }
    public UaStackServer getStackServer() {
        return stackServer;
    }

    public AddressSpaceManager getAddressSpaceManager() {
        return addressSpaceManager;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public OpcUaNamespace getOpcUaNamespace() {
        return opcUaNamespace;
    }

    public ServerNamespace getServerNamespace() {
        return serverNamespace;
    }

    public ServerTable getServerTable() {
        return serverTable;
    }

    public DataTypeManager getDataTypeManager() {
        return stackServer.getDataTypeManager();
    }

    public NamespaceTable getNamespaceTable() {
        return stackServer.getNamespaceTable();
    }

    public SerializationContext getSerializationContext() {
        return stackServer.getSerializationContext();
    }

    /**
     * Get the Server-wide {@link EventBus}.
     * <p>
     * Events posted to the EventBus are delivered synchronously to registered subscribers.
     *
     * @return the Server-wide {@link EventBus}.
     */
    public EventBus getEventBus() {
        return eventBus;
    }

    /**
     * Get the shared {@link EventFactory}.
     *
     * @return the shared {@link EventFactory}.
     */
    public EventFactory getEventFactory() {
        return eventFactory;
    }

    public ObjectTypeManager getObjectTypeManager() {
        return objectTypeManager;
    }

    public VariableTypeManager getVariableTypeManager() {
        return variableTypeManager;
    }

    public Map<UInteger, Subscription> getSubscriptions() {
        return subscriptions;
    }

    public Optional<KeyPair> getKeyPair(ByteString thumbprint) {
        return stackServer.getConfig().getCertificateManager().getKeyPair(thumbprint);
    }

    public Optional<X509Certificate> getCertificate(ByteString thumbprint) {
        return stackServer.getConfig().getCertificateManager().getCertificate(thumbprint);
    }

    public Optional<X509Certificate[]> getCertificateChain(ByteString thumbprint) {
        return stackServer.getConfig().getCertificateManager().getCertificateChain(thumbprint);
    }

    public ExecutorService getExecutorService() {
        return stackServer.getConfig().getExecutor();
    }

    public ScheduledExecutorService getScheduledExecutorService() {
        return SCHEDULED_EXECUTOR_SERVICE;
    }

    public ImmutableList<EndpointDescription> getEndpointDescriptions() {
        return stackServer.getEndpointDescriptions();
    }

    public Map<NodeId, ReferenceType> getReferenceTypes() {
        return referenceTypes;
    }

    public Map<ByteString, BrowseContinuationPoint> getBrowseContinuationPoints() {
        return browseContinuationPoints;
    }

}
