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

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class LdapTest {
    @RegisterExtension
    final LocalLdapServerExtension ldapServer = new LocalLdapServerExtension();

    private ApplicationDomain newDomain(LdapAdapter adapter) throws ConfigurationException {
        return new ApplicationDomain(domainConfig(), adapter);
    }

    private void ensureSystemExists(ApplicationDomain appDomain, String systemName)
            throws ConfigurationException, DirectoryException {
        if (!appDomain.systemExists(systemName)) {
            appDomain.createSystem(systemName);
        }
    }

    private void ensureUserExists(ApplicationDomain appDomain, LdapAdapter adapter, String userId, String cn, String sn)
            throws ConfigurationException, DirectoryException {
        String userDn = "uid=" + LdapAdapter.escapeDnValue(userId) + ",ou=Users,dc=test";
        try {
            if (appDomain.findObjectByDn(userDn) == null) {
                DefaultEntry userEntry = new DefaultEntry(new Dn(userDn));
                userEntry.add("objectClass", "top", "inetOrgPerson", "organizationalPerson", "person");
                userEntry.add("uid", userId);
                userEntry.add("cn", cn);
                userEntry.add("sn", sn);
                adapter.createObject(userEntry);
            }
        }
        catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
            fail(e.getMessage());
        }
    }

    private void ensureGroupExists(ApplicationDomain appDomain, LdapAdapter adapter, String groupId)
            throws ConfigurationException, DirectoryException {
        String groupDn = "ou=" + LdapAdapter.escapeDnValue(groupId) + ",ou=Groups,dc=test";
        try {
            if (appDomain.findObjectByDn(groupDn) == null) {
                DefaultEntry groupEntry = new DefaultEntry(new Dn(groupDn));
                groupEntry.add("objectClass", "organizationalUnit");
                groupEntry.add("ou", groupId);
                adapter.createObject(groupEntry);
            }
        }
        catch (org.apache.directory.api.ldap.model.exception.LdapException e) {
            fail(e.getMessage());
        }
    }

    private void ensureUserInGroup(ApplicationDomain appDomain, LdapAdapter adapter, String userId, String groupId)
            throws ConfigurationException, DirectoryException {
        String membershipDn = "cn=" + LdapAdapter.escapeDnValue(userId) + ",ou=" +
                LdapAdapter.escapeDnValue(groupId) + ",ou=Groups,dc=test";
        String userDn = "uid=" + LdapAdapter.escapeDnValue(userId) + ",ou=Users,dc=test";
        try {
            if (appDomain.findObjectByDn(membershipDn) == null) {
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
    }

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
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester"; // See line 122 in LocalLdapServer.java
            String userDn = appDomain.findUserDn(userId);
            assertEquals("uid=tester,ou=Users,dc=test", userDn);
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testFindingUserEscapesFilterCharacters() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "literal*)(uid=*";
            ensureUserExists(appDomain, adapter, userId, "Escaped", "Filter");
            String userDn = "uid=" + LdapAdapter.escapeDnValue(userId) + ",ou=Users,dc=test";

            assertEquals(userDn, appDomain.findUserDn(userId));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGlobalGroupsAndMembership() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupId = "Administrators";
            ensureUserInGroup(appDomain, adapter, userId, groupId);
            String membershipDn = "cn=" + userId + ",ou=" + groupId + ",ou=Groups,dc=test";

            assertNotNull(appDomain.findObjectByDn(membershipDn));
            assertTrue(appDomain.globalGroupExists(groupId));
            assertFalse(appDomain.globalGroupExists("MissingGroup"));
            assertTrue(appDomain.isMemberOfGlobalGroup(userId, groupId));

            Set<String> members = appDomain.getUsersInGlobalGroup(groupId);
            assertEquals(Set.of(userId), members);
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testRoleAssignmentAndLookup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "Datastore";
            ensureSystemExists(appDomain, systemName);

            String userId = "tester";
            String roleId = "Reader";
            String participationDn = appDomain.assignUserToRole(userId, roleId, systemName);
            assertNotNull(appDomain.findObjectByDn(participationDn));

            Set<String> users = appDomain.getUsersInRole(roleId, systemName);
            assertEquals(Set.of(userId), users);

            Set<String> roles = appDomain.getRolesInSystem(systemName);
            assertEquals(Set.of(roleId), roles);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testRoleAssignmentEscapesDnComponents() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "System, East";
            ensureSystemExists(appDomain, systemName);

            String userId = "tester";
            String roleId = "Reader, Tier 1";
            String participationDn = appDomain.assignUserToRole(userId, roleId, systemName);

            assertNotNull(appDomain.findObjectByDn(participationDn));
            assertTrue(appDomain.getUsersInRole(roleId, systemName).contains(userId));
            assertTrue(appDomain.getRolesInSystem(systemName).contains(roleId));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGroupRoleAssignment() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "Datastore";
            ensureSystemExists(appDomain, systemName);

            String groupId = "Administrators";
            String roleId = "Administrator";
            String participationDn = appDomain.assignGroupToRole(groupId, roleId, systemName);
            assertNotNull(appDomain.findObjectByDn(participationDn));

            Set<String> users = appDomain.getUsersInRole(roleId, systemName);
            assertEquals(Set.of(groupId), users);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testIndirectRoleAssignmentsViaGroup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String systemName = "Datastore";
            String roleId = "Auditor";

            ensureUserInGroup(appDomain, adapter, userId, groupId);

            ensureSystemExists(appDomain, systemName);
            appDomain.assignGroupToRole(groupId, roleId, systemName);

            Map<String, Set<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertEquals(Set.of(systemName), roles.keySet());
            assertEquals(Set.of(roleId), roles.get(systemName));

            String participationDn = LdapAdapter.compose(appDomain.groupInRoleDNTemplate, groupId, roleId, systemName);
            assertNotNull(appDomain.findObjectByDn(participationDn));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignUserToRoleWithMissingUserFails() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

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
            ApplicationDomain appDomain = newDomain(adapter);

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
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "IdempotentSystemUser";
            ensureSystemExists(appDomain, systemName);

            String userId = "tester";
            String roleId = "IdempotentRoleUser";
            appDomain.assignUserToRole(userId, roleId, systemName);
            appDomain.assignUserToRole(userId, roleId, systemName);

            Set<String> users = appDomain.getUsersInRole(roleId, systemName);
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
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "IdempotentSystemGroup";
            ensureSystemExists(appDomain, systemName);

            String groupId = "Administrators";
            String roleId = "IdempotentRoleGroup";
            appDomain.assignGroupToRole(groupId, roleId, systemName);
            appDomain.assignGroupToRole(groupId, roleId, systemName);

            Set<String> users = appDomain.getUsersInRole(roleId, systemName);
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
            ApplicationDomain appDomain = newDomain(adapter);

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
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupId = "Administrators";
            ensureUserInGroup(appDomain, adapter, userId, groupId);

            Set<String> groups = appDomain.getGlobalGroups();
            assertEquals(Set.of("Administrators", "Guests"), groups);
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetRolesInSystemExcludesMembershipEntries() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "RolesListSystem";
            ensureSystemExists(appDomain, systemName);

            String userId = "tester";
            String roleId = "Observer";
            appDomain.assignUserToRole(userId, roleId, systemName);

            Set<String> roles = appDomain.getRolesInSystem(systemName);
            assertEquals(Set.of(roleId), roles);
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssignGroupToRolePreventsDuplicateMembershipEntries() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "DedupSystem";
            ensureSystemExists(appDomain, systemName);

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
    public void testCreateSystemEscapesDnComponents() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String systemName = "bad,system";
            String systemDn = appDomain.createSystem(systemName);

            assertEquals("ou=bad\\,system,ou=Systems,dc=test", systemDn);
            assertTrue(appDomain.systemExists(systemName));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testDirectAndIndirectRolesUnionWithoutDuplicates() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupId = "Administrators";
            String systemName = "UnionSystem";
            String roleId = "UnionRole";

            ensureUserInGroup(appDomain, adapter, userId, groupId);

            ensureSystemExists(appDomain, systemName);
            appDomain.assignGroupToRole(groupId, roleId, systemName);
            appDomain.assignUserToRole(userId, roleId, systemName);

            Map<String, Set<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertEquals(Set.of(systemName), roles.keySet());
            assertEquals(Set.of(roleId), roles.get(systemName));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testMultipleGroupsAndRolesAcrossSystems() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupA = "Administrators";
            String groupB = "Guests";
            String systemA = "SystemA";
            String systemB = "SystemB";
            String roleA = "RoleA";
            String roleB = "RoleB";

            ensureUserInGroup(appDomain, adapter, userId, groupA);
            ensureUserInGroup(appDomain, adapter, userId, groupB);

            ensureSystemExists(appDomain, systemA);
            ensureSystemExists(appDomain, systemB);

            appDomain.assignGroupToRole(groupA, roleA, systemA);
            appDomain.assignGroupToRole(groupB, roleB, systemB);

            Map<String, Set<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertEquals(Set.of(systemA, systemB), roles.keySet());
            assertEquals(Set.of(roleA), roles.get(systemA));
            assertEquals(Set.of(roleB), roles.get(systemB));
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGroupMembershipWithoutRolesYieldsEmptyRoles() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "noRoleUser";
            String groupId = "NoRoleGroup";
            ensureGroupExists(appDomain, adapter, groupId);
            ensureUserExists(appDomain, adapter, userId, "NoRole", "User");
            ensureUserInGroup(appDomain, adapter, userId, groupId);

            Map<String, Set<String>> roles = appDomain.groupsAndRolesAnalysis(userId);
            assertTrue(roles.isEmpty());
        }
        catch (ConfigurationException | DirectoryException | InvalidParameterException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testMultipleUsersInGlobalGroup() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String groupId = "Administrators";
            ensureUserExists(appDomain, adapter, "second", "Second", "User");
            ensureUserInGroup(appDomain, adapter, "tester", groupId);
            ensureUserInGroup(appDomain, adapter, "second", groupId);

            Set<String> members = appDomain.getUsersInGlobalGroup(groupId);
            assertEquals(Set.of("tester", "second"), members);
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testIsMemberOfGlobalGroupWithOuDnInput() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            String userId = "tester";
            String groupId = "Administrators";
            ensureUserInGroup(appDomain, adapter, userId, groupId);

            assertTrue(appDomain.isMemberOfGlobalGroup(userId, "ou=" + groupId + ",ou=Groups,dc=test"));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetRolesInMissingSystemReturnsEmptySet() {
        try (LdapAdapter adapter = new LdapAdapter(adapterConfig())) {
            ApplicationDomain appDomain = newDomain(adapter);

            assertEquals(Set.of(), appDomain.getRolesInSystem("MissingSystem"));
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }
}
