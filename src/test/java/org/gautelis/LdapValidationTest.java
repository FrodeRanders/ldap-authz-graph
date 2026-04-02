/*
 * Copyright (C) 2026 Frode Randers
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.gautelis;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class LdapValidationTest {

    @Test
    public void testComposeRejectsTooManyComponents() {
        assertThrows(
            ConfigurationException.class,
            () -> LdapAdapter.compose("ou=%s,dc=test", "one", "two")
        );
    }

    @Test
    public void testComposeRejectsTooFewComponents() {
        assertThrows(
            ConfigurationException.class,
            () -> LdapAdapter.compose("ou=%s,ou=%s,dc=test", "one")
        );
    }

    @Test
    public void testComposeEscapesDnComponents() throws ConfigurationException {
        assertEquals(
            "ou=bad\\,system,ou=Systems,dc=test",
            LdapAdapter.compose("ou=%s,ou=Systems,dc=test", "bad,system")
        );
    }

    @Test
    public void testEscapeFilterValue() {
        assertEquals("literal\\2A\\29\\28uid=\\2A", LdapAdapter.escapeFilterValue("literal*)(uid=*"));
    }

    @Test
    public void testApplicationDomainRejectsInvalidTemplateConfiguration() {
        Map<String, String> invalidConfig = Map.of(
            ApplicationDomain.LDAP_USER_ID, "uid",
            ApplicationDomain.LDAP_USER_DN_TEMPLATE, "uid=%s,ou=Users,dc=test",
            ApplicationDomain.LDAP_USERS_CONTEXT, "ou=Users,dc=test",
            ApplicationDomain.LDAP_GROUPS_CONTEXT, "ou=Groups,dc=test",
            ApplicationDomain.LDAP_SYSTEMS_CONTEXT, "ou=Systems,dc=test",
            ApplicationDomain.LDAP_ROLE_DN_TEMPLATE, "ou=%s,ou=Roles,dc=test"
        );

        assertThrows(
            ConfigurationException.class,
            () -> new ApplicationDomain(invalidConfig, null)
        );
    }

    @Test
    public void testApplicationDomainRejectsBlankContextConfiguration() {
        Map<String, String> invalidConfig = Map.of(
            ApplicationDomain.LDAP_USER_ID, "uid",
            ApplicationDomain.LDAP_USER_DN_TEMPLATE, "uid=%s,ou=Users,dc=test",
            ApplicationDomain.LDAP_USERS_CONTEXT, " ",
            ApplicationDomain.LDAP_GROUPS_CONTEXT, "ou=Groups,dc=test",
            ApplicationDomain.LDAP_SYSTEMS_CONTEXT, "ou=Systems,dc=test"
        );

            assertThrows(
                ConfigurationException.class,
            () -> new ApplicationDomain(invalidConfig, null)
        );
    }

    @Test
    public void testLdapAdapterRejectsInvalidPoolIntegerConfiguration() {
        Map<String, String> invalidConfig = Map.of(
            LdapAdapter.LDAP_HOST, "localhost",
            LdapAdapter.LDAP_PORT, "10389",
            LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test",
            LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret",
            LdapAdapter.LDAP_POOL_MAX_TOTAL, "not-a-number"
        );

        assertThrows(
            ConfigurationException.class,
            () -> new LdapAdapter(invalidConfig)
        );
    }

    @Test
    public void testLdapAdapterRejectsInvalidPoolBounds() {
        Map<String, String> invalidConfig = Map.of(
            LdapAdapter.LDAP_HOST, "localhost",
            LdapAdapter.LDAP_PORT, "10389",
            LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test",
            LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret",
            LdapAdapter.LDAP_POOL_MAX_TOTAL, "4",
            LdapAdapter.LDAP_POOL_MAX_IDLE, "2",
            LdapAdapter.LDAP_POOL_MIN_IDLE, "3"
        );

        assertThrows(
            ConfigurationException.class,
            () -> new LdapAdapter(invalidConfig)
        );
    }

    @Test
    public void testReadFailurePreservesReleaseFailureAsSuppressed() {
        LdapConnection connection = (LdapConnection) Proxy.newProxyInstance(
            LdapConnection.class.getClassLoader(),
            new Class<?>[]{LdapConnection.class},
            (proxy, method, args) -> null
        );

        LdapAdapter adapter = new LdapAdapter(new LdapAdapter.ConnectionManager() {
            @Override
            public LdapConnection getConnection() {
                return connection;
            }

            @Override
            public void releaseConnection(LdapConnection connection) {
                throw new IllegalStateException("release failed");
            }

            @Override
            public void close() {
            }
        });

        DirectoryReadException exception = assertThrows(
            DirectoryReadException.class,
            () -> adapter.findObject(ignored -> {
                throw new LdapException("primary failure");
            })
        );

        assertEquals("Could not find object in directory: primary failure", exception.getMessage());
        assertEquals(1, exception.getSuppressed().length);
        assertEquals(DirectoryConnectionException.class, exception.getSuppressed()[0].getClass());
        assertEquals("Could not release connection back to pool: release failed", exception.getSuppressed()[0].getMessage());
    }
}
