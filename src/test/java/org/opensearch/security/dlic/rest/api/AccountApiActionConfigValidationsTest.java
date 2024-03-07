/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.dlic.rest.api;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.password4j.BcryptFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;
import org.junit.Test;
import org.mockito.Mockito;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.support.ConfigConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AccountApiActionConfigValidationsTest extends AbstractApiActionValidationTest {

    @Test
    public void verifyValidCurrentPassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies);

        final var u = createExistingUser();

        boolean fipsEnabled = clusterService.getSettings().getAsBoolean(ConfigConstants.SECURITY_FIPS_MODE_ENABLED_KEY, false);

        var result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        u.setHash(Utils.hash("aaaa".toCharArray(), fipsEnabled));
        result = accountApiAction.validCurrentPassword(SecurityConfiguration.of(requestContent(), "u", configuration));
        assertTrue(result.isValid());
    }

    @Test
    public void updatePassword() {
        final var accountApiAction = new AccountApiAction(clusterService, threadPool, securityApiDependencies);

        final var requestContent = requestContent();
        requestContent.remove("password");
        final var u = createExistingUser();
        u.setHash(null);

        final boolean fipsEnabled = clusterService.getSettings().getAsBoolean(ConfigConstants.SECURITY_FIPS_MODE_ENABLED_KEY, false);

        var result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertFalse(result.isValid());
        assertEquals(RestStatus.BAD_REQUEST, result.status());

        requestContent.put("password", "cccccc");
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertTrue(result.isValid());
        assertTrue(Password.check("cccccc", u.getHash()).with(BcryptFunction.getInstance(Bcrypt.B,12)));
        requestContent.remove("password");
        requestContent.put("hash", Utils.hash("dddddd".toCharArray(),fipsEnabled));
        result = accountApiAction.updatePassword(SecurityConfiguration.of(requestContent, "u", configuration));
        assertTrue(result.isValid());
        assertTrue(Password.check("dddddd", u.getHash()).with(BcryptFunction.getInstance(Bcrypt.B,12)));
    }

    private ObjectNode requestContent() {
        return objectMapper.createObjectNode().put("current_password", "aaaa").put("password", "bbbb");
    }

    private InternalUserV7 createExistingUser() {
        final var u = new InternalUserV7();
        u.setHash(Utils.hash("sssss".toCharArray(), false));
        Mockito.<Object>when(configuration.getCEntry("u")).thenReturn(u);
        return u;
    }

}
