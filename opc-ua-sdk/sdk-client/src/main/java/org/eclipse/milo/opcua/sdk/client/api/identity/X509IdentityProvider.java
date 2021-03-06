/*
 * Copyright (c) 2019 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.client.api.identity;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.util.Arrays;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.SignatureData;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.eclipse.milo.opcua.stack.core.types.structured.X509IdentityToken;
import org.eclipse.milo.opcua.stack.core.util.NonceUtil;
import org.eclipse.milo.opcua.stack.core.util.SignatureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.eclipse.milo.opcua.stack.core.util.ConversionUtil.l;

public class X509IdentityProvider implements IdentityProvider {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public X509IdentityProvider(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public SignedIdentityToken getIdentityToken(EndpointDescription endpoint,
                                                ByteString serverNonce) throws Exception {

        List<UserTokenPolicy> userIdentityTokens = l(endpoint.getUserIdentityTokens());

        UserTokenPolicy tokenPolicy = userIdentityTokens.stream()
            .filter(t -> t.getTokenType() == UserTokenType.Certificate)
            .findFirst().orElseThrow(() -> new Exception("no x509 certificate token policy found"));

        String policyId = tokenPolicy.getPolicyId();

        SecurityPolicy securityPolicy = SecurityPolicy.None;

        String securityPolicyUri = tokenPolicy.getSecurityPolicyUri();

        try {
            if (securityPolicyUri != null && !securityPolicyUri.isEmpty()) {
                securityPolicy = SecurityPolicy.fromUri(securityPolicyUri);
            } else {
                securityPolicyUri = endpoint.getSecurityPolicyUri();
                securityPolicy = SecurityPolicy.fromUri(securityPolicyUri);
            }
        } catch (Throwable t) {
            logger.warn("Error parsing SecurityPolicy for uri={}", securityPolicyUri);
        }

        NonceUtil.validateNonce(serverNonce);

        if (serverNonce.length() > 0 && Arrays.areAllZeroes(serverNonce.bytesOrEmpty(), 0, serverNonce.length())) {
            throw new UaException(StatusCodes.Bad_NonceInvalid, "nonce must be non-zero");
        }

        X509IdentityToken token = new X509IdentityToken(
            policyId,
            ByteString.of(certificate.getEncoded())
        );

        byte[] serverCertificateBytes = new byte[0];
        if (!endpoint.getSecurityPolicyUri().equals(SecurityPolicy.None.getUri())) {
            ByteString serverCertificate = endpoint.getServerCertificate();
            serverCertificateBytes = serverCertificate.bytesOrEmpty();
        }

        byte[] serverNonceBytes = serverNonce.bytes();
        if (serverNonceBytes == null) serverNonceBytes = new byte[0];

        byte[] signature = SignatureUtil.sign(
            securityPolicy.getAsymmetricSignatureAlgorithm(),
            privateKey,
            ByteBuffer.wrap(serverCertificateBytes),
            ByteBuffer.wrap(serverNonceBytes)
        );

        SignatureData signatureData = new SignatureData(
            securityPolicy.getAsymmetricSignatureAlgorithm().getUri(),
            ByteString.of(signature)
        );

        return new SignedIdentityToken(token, signatureData);
    }

}
