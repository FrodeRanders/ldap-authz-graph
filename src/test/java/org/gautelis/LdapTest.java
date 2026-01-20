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

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class LdapTest {
    @RegisterExtension
    static final LocalLdapServerExtension LDAP_SERVER = new LocalLdapServerExtension();

    private Map<String, String> adapterConfig() {
        return Map.of(
            // Where to locate directory service
            LdapAdapter.LDAP_HOST, "localhost",
            LdapAdapter.LDAP_PORT, "10389", // See line 137 in LocalLdapServer.java

            // How to bind to directory service in order to search for users, etc.
            LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test",
            LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret" // See line 97 in LocalLdapServer.java
        );
    }

    private Map<String, String> domainConfig() {
        return Map.of(
            ApplicationDomain.LDAP_USER_ID, "uid",
            ApplicationDomain.LDAP_USER_DN_TEMPLATE, "uid=%s,ou=Users,dc=test",
            ApplicationDomain.LDAP_USERS_CONTEXT, "ou=Users,dc=test",
            ApplicationDomain.LDAP_GROUPS_CONTEXT, "ou=Groups,dc=test",
            ApplicationDomain.LDAP_SYSTEMS_CONTEXT, "ou=Systems,dc=test"
        );
    }

    @Test
    public void testFindingUser() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {

            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester"; // See line 122 in LocalLdapServer.java
            System.out.println("Looking for user with id = " + userId);
            System.out.println("  by means of ApplicationDomain::findUserDn()");
            System.out.println("  using the (configurable) parameters:");
            System.out.println("    userObjectClass = '" + appDomain.userObjectClass + "'");
            System.out.println("    userIdAttribute = '" + appDomain.userIdAttribute + "'");
            System.out.println("    usersContext = '" + appDomain.usersContext + "'");


            String userDn = appDomain.findUserDn(userId);
            System.out.println("Found '" + userId + "' to be '" + userDn + "' (a distinguished name)");
            System.out.println();
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGlobalGroupsAndMembership() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            assertTrue(appDomain.findObjectByDn(membershipDn) != null);
            assertTrue(appDomain.globalGroupExists(groupId));
            assertFalse(appDomain.globalGroupExists("MissingGroup"));
            assertTrue(appDomain.isMemberOfGlobalGroup(userId, groupId));

            Collection<String> members = appDomain.getUsersInGlobalGroup(groupId);
            assertTrue(members.contains(userId));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testRoleAssignmentAndLookup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "Datastore";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String userId = "tester";
            String roleId = "Reader";
            String participationDn = appDomain.assignUserToRole(userId, roleId, systemName);
            assertTrue(appDomain.findObjectByDn(participationDn) != null);

            Collection<String> users = appDomain.getUsersInRole(roleId, systemName);
            assertTrue(users.contains(userId));

            Collection<String> roles = appDomain.getRolesInSystem(systemName);
            assertTrue(roles.contains(roleId));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGroupRoleAssignment() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "Datastore";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String groupId = "Administrators";
            String roleId = "Administrator";
            String participationDn = appDomain.assignGroupToRole(groupId, roleId, systemName);
            assertTrue(appDomain.findObjectByDn(participationDn) != null);

            Collection<String> users = appDomain.getUsersInRole(roleId, systemName);
            assertTrue(users.contains(groupId));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testIndirectRoleAssignmentsViaGroup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String systemName = "Datastore";
            String roleId = "Auditor";

            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }
            appDomain.assignGroupToRole(groupId, roleId, systemName);

            Hashtable<String, java.util.HashSet<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertTrue(roles.containsKey(systemName));
            assertTrue(roles.get(systemName).contains(roleId));

            String participationDn = LdapAdapter.compose(appDomain.groupInRoleDNTemplate, groupId, roleId, systemName);
            assertTrue(appDomain.findObjectByDn(participationDn) != null);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignUserToRoleWithMissingUserFails() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            assertThrows(
                InvalidParameterException.class,
                () -> appDomain.assignUserToRole("missing-user", "Reader", "Datastore")
            );
        }
        catch (ConfigurationException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignGroupToRoleWithMissingGroupFails() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            assertThrows(
                InvalidParameterException.class,
                () -> appDomain.assignGroupToRole("MissingGroup", "Reader", "Datastore")
            );
        }
        catch (ConfigurationException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignUserToRoleIsIdempotent() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "IdempotentSystemUser";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String userId = "tester";
            String roleId = "IdempotentRoleUser";
            appDomain.assignUserToRole(userId, roleId, systemName);
            appDomain.assignUserToRole(userId, roleId, systemName);

            Collection<String> users = appDomain.getUsersInRole(roleId, systemName);
            long occurrences = users.stream().filter(userId::equals).count();
            assertEquals(1, occurrences);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignGroupToRoleIsIdempotent() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "IdempotentSystemGroup";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String groupId = "Administrators";
            String roleId = "IdempotentRoleGroup";
            appDomain.assignGroupToRole(groupId, roleId, systemName);
            appDomain.assignGroupToRole(groupId, roleId, systemName);

            Collection<String> users = appDomain.getUsersInRole(roleId, systemName);
            long occurrences = users.stream().filter(groupId::equals).count();
            assertEquals(1, occurrences);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testFindObjectByDnReturnsNullWhenMissing() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String missingDn = "cn=missing,ou=Users,dc=test";
            assertNull(appDomain.findObjectByDn(missingDn));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetGlobalGroupsExcludesMembershipEntries() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            Collection<String> groups = appDomain.getGlobalGroups();
            assertTrue(groups.contains("Administrators"));
            assertTrue(groups.contains("Guests"));
            assertFalse(groups.contains(userId));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetRolesInSystemExcludesMembershipEntries() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "RolesListSystem";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String userId = "tester";
            String roleId = "Observer";
            appDomain.assignUserToRole(userId, roleId, systemName);

            Collection<String> roles = appDomain.getRolesInSystem(systemName);
            assertTrue(roles.contains(roleId));
            assertFalse(roles.contains(userId));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignGroupToRolePreventsDuplicateMembershipEntries() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String systemName = "DedupSystem";
            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }

            String groupId = "Administrators";
            String roleId = "DedupRole";
            appDomain.assignGroupToRole(groupId, roleId, systemName);
            appDomain.assignGroupToRole(groupId, roleId, systemName);

            String roleDn = LdapAdapter.compose(appDomain.roleDNTemplate, roleId, systemName);
            String filter = "(objectClass=groupOfNames)";
            long count = adapter.findObjects(adapter.shallowSearchWithFilter(roleDn, filter, "cn")).size();
            assertEquals(1, count);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testCreateSystemWithInvalidNameFails() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            assertThrows(
                ConfigurationException.class,
                () -> appDomain.createSystem("bad,system")
            );
        }
        catch (ConfigurationException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testDirectAndIndirectRolesUnionWithoutDuplicates() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String systemName = "UnionSystem";
            String roleId = "UnionRole";

            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            if (!appDomain.systemExists(systemName)) {
                appDomain.createSystem(systemName);
            }
            appDomain.assignGroupToRole(groupId, roleId, systemName);
            appDomain.assignUserToRole(userId, roleId, systemName);

            Hashtable<String, java.util.HashSet<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertTrue(roles.containsKey(systemName));
            assertTrue(roles.get(systemName).contains(roleId));
            assertEquals(1, roles.get(systemName).stream().filter(roleId::equals).count());
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testMultipleGroupsAndRolesAcrossSystems() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupA = "Administrators";
            String groupB = "Guests";
            String systemA = "SystemA";
            String systemB = "SystemB";
            String roleA = "RoleA";
            String roleB = "RoleB";

            String membershipDnA = "cn=" + userId + ",ou=" + groupA + ",ou=Groups,dc=test";
            String membershipDnB = "cn=" + userId + ",ou=" + groupB + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDnA)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDnA));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
                if (null == appDomain.findObjectByDn(membershipDnB)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDnB));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            if (!appDomain.systemExists(systemA)) {
                appDomain.createSystem(systemA);
            }
            if (!appDomain.systemExists(systemB)) {
                appDomain.createSystem(systemB);
            }

            appDomain.assignGroupToRole(groupA, roleA, systemA);
            appDomain.assignGroupToRole(groupB, roleB, systemB);

            Hashtable<String, java.util.HashSet<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertTrue(roles.containsKey(systemA));
            assertTrue(roles.containsKey(systemB));
            assertTrue(roles.get(systemA).contains(roleA));
            assertTrue(roles.get(systemB).contains(roleB));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGroupMembershipWithoutRolesYieldsEmptyRoles() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "noRoleUser";
            String groupId = "NoRoleGroup";
            String userDn = "uid=" + userId + ",ou=Users,dc=test";
            String groupDn = "ou=" + groupId + ",ou=Groups,dc=test";
            String membershipDn = "cn=" + userId + "," + groupDn;

            try {
                if (null == appDomain.findObjectByDn(groupDn)) {
                    DefaultEntry groupEntry = new DefaultEntry(new Dn(groupDn));
                    groupEntry.add("objectClass", "organizationalUnit");
                    groupEntry.add("ou", groupId);
                    adapter.createObject(groupEntry);
                }
                if (null == appDomain.findObjectByDn(userDn)) {
                    DefaultEntry userEntry = new DefaultEntry(new Dn(userDn));
                    userEntry.add("objectClass", "top", "inetOrgPerson", "organizationalPerson", "person");
                    userEntry.add("uid", userId);
                    userEntry.add("cn", "NoRole");
                    userEntry.add("sn", "User");
                    adapter.createObject(userEntry);
                }
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", userDn);
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            Hashtable<String, java.util.HashSet<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertTrue(roles.isEmpty());
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testMultipleUsersInGlobalGroup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String groupId = "Administrators";

            String testerMembershipDn = "cn=tester,ou=" + groupId + ",ou=Groups,dc=test";
            String otherMembershipDn = "cn=second,ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(testerMembershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(testerMembershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", "tester");
                    membership.add("member", "uid=tester,ou=Users,dc=test");
                    adapter.createObject(membership);
                }
                if (null == appDomain.findObjectByDn(otherMembershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(otherMembershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", "second");
                    membership.add("member", "uid=tester,ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            Collection<String> members = appDomain.getUsersInGlobalGroup(groupId);
            assertTrue(members.contains("tester"));
            assertTrue(members.contains("second"));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testIsMemberOfGlobalGroupWithOuDnInput() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = new ApplicationDomain(domainConfig(), adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";
            try {
                if (null == appDomain.findObjectByDn(membershipDn)) {
                    DefaultEntry membership = new DefaultEntry(new Dn(membershipDn));
                    membership.add("objectClass", "groupOfNames");
                    membership.add("cn", userId);
                    membership.add("member", "uid=" + userId + ",ou=Users,dc=test");
                    adapter.createObject(membership);
                }
            }
            catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
                fail(e.getMessage());
            }

            assertTrue(appDomain.isMemberOfGlobalGroup(userId, "ou=" + groupId + ",ou=Groups,dc=test"));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }
}
