package org.eclipse.milo.opcua.stack.server.services;

import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;

public interface LocalDiscoveryServiceSet {
	default void onFindServers(ServiceRequest serviceRequest) throws UaException {
		serviceRequest.setServiceFault(StatusCodes.Bad_ServiceUnsupported);
	}

	default void onGetEndpoints(ServiceRequest serviceRequest) throws UaException {
		serviceRequest.setServiceFault(StatusCodes.Bad_ServiceUnsupported);
	}

	default void onRegister2Server(ServiceRequest serviceRequest) throws UaException {
		serviceRequest.setServiceFault(StatusCodes.Bad_ServiceUnsupported);
	}

	default void onRegisterServer(ServiceRequest serviceRequest) throws UaException {
		serviceRequest.setServiceFault(StatusCodes.Bad_ServiceUnsupported);
	}
}
