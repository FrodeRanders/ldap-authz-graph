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

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


/**
 * Manages a connection to an LDAP directory service and executes
 * queries and updates through it.
 */
public class ApplicationDomain {
    static final Logger log = LoggerFactory.getLogger(ApplicationDomain.class);


    /**
     * Base distinguished name.
     * A typical value is
     * <I>"dc=test"</I>
     */
    // public static final String LDAP_BASE_DN = "LDAP_BASE_DN";

    /**
     * The systems context
     * <p/>
     * A typical value is
     * <I>"ou=Systems,dc=test"</I>
     */
    public static final String LDAP_SYSTEMS_CONTEXT = "LDAP_SYSTEMS_CONTEXT";

    /**
     * The users context
     * <p/>
     * A typical value is
     * <I>"ou=Users,dc=test"</I>
     */
    public static final String LDAP_USERS_CONTEXT = "LDAP_USERS_CONTEXT";

    /**
     * The global groups context
     * <p/>
     * A typical value is
     * <I>"ou=Groups,dc=test"</I>
     */
    public static final String LDAP_GROUPS_CONTEXT = "LDAP_GROUPS_CONTEXT";


    /**
     * The archive roles distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_ROLES_DN_TEMPLATE = "LDAP_ROLES_DN_TEMPLATE";

    /**
     * The user object class.
     * <p/>
     * A typical value is
     * <I>"user"</I>
     */
    public static final String LDAP_USER_OBJECT_CLASS = "LDAP_USER_OBJECT_CLASS";

    /**
     * The system administration role distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=Administrator,ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_ADMIN_ROLE_DN_TEMPLATE = "LDAP_ADMIN_ROLE_DN_TEMPLATE";

    /**
     * The archive user role distinguished name template
     * <P>
     * A typical value is
     * <I>"ou=User,ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_USER_ROLE_DN_TEMPLATE = "LDAP_USER_ROLE_DN_TEMPLATE";

    /**
     * The archive specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_ROLE_DN_TEMPLATE = "LDAP_ROLE_DN_TEMPLATE";

    /**
     * The global specific group distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Groups,dc=test"</I>
     */
    public static final String LDAP_GROUP_DN_TEMPLATE = "LDAP_GROUP_DN_TEMPLATE";

    /**
     * The user in system-specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_USER_IN_ROLE_DN_TEMPLATE = "LDAP_USER_IN_ROLE_DN_TEMPLATE";

    /**
     * The global group in system-specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_GROUP_IN_ROLE_DN_TEMPLATE = "LDAP_GROUP_IN_ROLE_DN_TEMPLATE";

    /**
     * The user in specific global group distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=Groups,dc=test"</I>
     */
    public static final String LDAP_USER_IN_GROUP_DN_TEMPLATE = "LDAP_USER_IN_GROUP_DN_TEMPLATE";

    /**
     * The system distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Systems,dc=test"</I>
     */
    public static final String LDAP_SYSTEM_DN_TEMPLATE = "LDAP_SYSTEM_DN_TEMPLATE";

    /**
     * The user distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=Users,dc=test"</I>
     */
    public static final String LDAP_USER_DN_TEMPLATE = "LDAP_USER_DN_TEMPLATE";

    /**
     * The foreign user distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=ForeignUsers,dc=test"</I>
     */
    public static final String LDAP_FOREIGN_USER_DN_TEMPLATE = "LDAP_FOREIGN_USER_DN_TEMPLATE";

    /**
     * The foreign domain distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=ForeignUsers,dc=test"</I>
     */
    public static final String LDAP_FOREIGN_DOMAIN_DN_TEMPLATE = "LDAP_FOREIGN_DOMAIN_DN_TEMPLATE";

    /**
     * The user search filter
     * <p/>
     * A typical value is
     * <I>"(cn=*)"</I>
     */
    public static final String LDAP_USER_SEARCH_FILTER = "LDAP_USER_SEARCH_FILTER";

    /**
     * The global group search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_GROUP_SEARCH_FILTER = "LDAP_GROUP_SEARCH_FILTER";

    /**
     * The system specific role search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_ROLE_SEARCH_FILTER = "LDAP_ROLE_SEARCH_FILTER";

    /**
     * The system search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_SYSTEM_SEARCH_FILTER = "LDAP_SYSTEM_SEARCH_FILTER";

    /**
     * The membership attribute
     * <p/>
     * A typical value is
     * <I>"member"</I>
     */
    public static final String LDAP_MEMBERSHIP_ATTRIBUTE = "LDAP_MEMBERSHIP_ATTRIBUTE";

    /**
     * The membership object class
     * <p/>
     * A typical value is
     * <I>"groupOfNames"</I>
     */
    public static final String LDAP_MEMBERSHIP_OBJECTCLASS = "LDAP_MEMBERSHIP_OBJECTCLASS";

    /**
     * The user id attribute name
     * <p/>
     * A typical value is
     * <I>"uid"</I>
     */
    public static final String LDAP_USER_ID = "LDAP_USER_ID";

    /**
     * The user password attribute name
     * <p/>
     * A typical value is
     * <I>"userPassword"</I>
     */
    public static final String LDAP_USER_PASSWORD = "LDAP_USER_PASSWORD";

    /**
     * The user given name attribute name
     * <p/>
     * A typical value is
     * <I>"givenName"</I>
     */
    public static final String LDAP_USER_FIRST_NAME = "LDAP_USER_FIRST_NAME";

    /**
     * The user surname attribute name
     * <p/>
     * A typical value is
     * <I>"sn"</I>
     */
    public static final String LDAP_USER_LAST_NAME = "LDAP_USER_LAST_NAME";

    /**
     * The user language attribute name
     * <p/>
     * A typical value is
     * <I>"language"</I>
     */
    public static final String LDAP_USER_LANGUAGE = "LDAP_USER_LANGUAGE";

    /**
     * The user authorization level attribute name
     * <p/>
     * A typical value is
     * <I>"authorizationLevel"</I>
     */
    public static final String LDAP_USER_AUTHORIZATION_LEVEL = "LDAP_USER_AUTHORIZATION_LEVEL";

    /**
     * The user user interface detail level attribute name
     * <p/>
     * A typical value is
     * <I>"uiDetailLevel"</I>
     */
    public static final String LDAP_USER_UI_DETAIL_LEVEL = "LDAP_USER_UI_DETAIL_LEVEL";

    /**
     * The user email attribute name
     * <p/>
     * A typical value is
     * <I>"mail"</I>
     */
    public static final String LDAP_USER_MAIL = "LDAP_USER_MAIL";

    /**
     * The global group id attribute name
     * <p/>
     * A typical value is
     * <I>"ou"</I>
     */
    public static final String LDAP_GROUP_ID = "LDAP_GROUP_ID";

    /**
     * The global group description attribute name
     * <p/>
     * A typical value is
     * <I>"description"</I>
     */
    public static final String LDAP_GROUP_DESCRIPTION = "LDAP_GROUP_DESCRIPTION";

    /**
     * The system name attribute name
     * <p/>
     * A typical value is
     * <I>"ou"</I>
     */
    public static final String LDAP_SYSTEM_NAME_ATTRIBUTE = "LDAP_SYSTEM_NAME_ATTRIBUTE";

    /**
     * The name of the Administrator role
     */
    public final static String ADMINISTRATOR_ROLE = "Administrator";

    /**
     * The name of the User role
     */
    public final static String USER_ROLE = "User";

    /**
     * The name of the global administrators group
     */
    public final static String ADMINISTRATORS_GROUP = "Administrators";

    //------------------------------------------------------------------------
    private final static Rdn[] RdnT = {};

    // System
    protected final String systemDNTemplate;
    protected final String systemSearchFilter;
    protected final String systemNameAttribute;

    // Object classes
    protected final String userObjectClass;
    protected final String membershipObjectClass;

    // User
    protected final String userDNTemplate;
    protected final String userSearchFilter;

    // Foreign users
    protected final String foreignUserDNTemplate;
    protected final String foreignDomainDNTemplate;

    // User attributes names
    protected final String userIdAttribute;
    protected final String passwordAttribute;
    protected final String firstNameAttribute;
    protected final String lastNameAttribute;

    // Membership attribute name
    protected final String membershipAttribute;

    // Role
    protected final String roleDNTemplate;
    protected final String roleSearchFilter;
    protected final String userInRoleDNTemplate;
    protected final String groupInRoleDNTemplate;

    // Group
    protected final String groupDNTemplate;
    protected final String groupSearchFilter;
    protected final String userInGroupDNTemplate;
    protected final String groupIdAttribute;
    protected final String groupDescriptionAttribute;

    // Roles
    protected final String rolesDNTemplate;

    //
    protected final String usersContext;
    protected final String groupsContext;
    protected final String systemsContext;

    //
    protected final LdapAdapter adapter;

    public ApplicationDomain(Map<String, String> config) throws ConfigurationException {
        this(config, new LdapAdapter(config));
    }
    public ApplicationDomain(Map<String, String> config, LdapAdapter adapter) {
        this.adapter = adapter;

        // === Init application specifics ===

        //--------------------------------------------------------------------------
        // -- Object classes --
        //
        // Examples; "Person", "inetOrgPerson", ...
        //--------------------------------------------------------------------------
        userObjectClass =
                config.getOrDefault(LDAP_USER_OBJECT_CLASS, "inetOrgPerson");
        membershipObjectClass =
                config.getOrDefault(LDAP_MEMBERSHIP_OBJECTCLASS, "groupOfNames");

        //--------------------------------------------------------------------------
        // -- User attributes --
        //--------------------------------------------------------------------------
        userIdAttribute =
                config.getOrDefault(LDAP_USER_ID, "uid"); // or cn, sAMAccountName, ...
        passwordAttribute =
                config.getOrDefault(LDAP_USER_PASSWORD, "userPassword");
        firstNameAttribute =
                config.getOrDefault(LDAP_USER_FIRST_NAME, "givenName");
        lastNameAttribute =
                config.getOrDefault(LDAP_USER_LAST_NAME, "sn");

        //--------------------------------------------------------------------------
        // -- Membership attributes --
        //--------------------------------------------------------------------------
        membershipAttribute =
                config.getOrDefault(LDAP_MEMBERSHIP_ATTRIBUTE, "member");

        //--------------------------------------------------------------------------
        // -- Templates for various distinguished names --
        //--------------------------------------------------------------------------
        roleDNTemplate =
                config.getOrDefault(LDAP_ROLE_DN_TEMPLATE, "ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test");
        groupDNTemplate =
                config.getOrDefault(LDAP_GROUP_DN_TEMPLATE, "ou=%s,ou=Groups,dc=test");
        userInRoleDNTemplate =
                config.getOrDefault(LDAP_USER_IN_ROLE_DN_TEMPLATE, "cn=%s,ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test");
        groupInRoleDNTemplate = // If not explicitly configured, reuse the same template
                config.getOrDefault(LDAP_GROUP_IN_ROLE_DN_TEMPLATE, userInRoleDNTemplate);
        userInGroupDNTemplate =
                config.getOrDefault(LDAP_USER_IN_GROUP_DN_TEMPLATE, "cn=%s,ou=%s,ou=Groups,dc=test");
        systemDNTemplate =
                config.getOrDefault(LDAP_SYSTEM_DN_TEMPLATE, "ou=%s,ou=Systems,dc=test");
        rolesDNTemplate =
                config.getOrDefault(LDAP_ROLES_DN_TEMPLATE, "ou=Roles,ou=%s,ou=Systems,dc=test");
        userDNTemplate =
                config.getOrDefault(LDAP_USER_DN_TEMPLATE, "cn=%s,ou=Users,dc=test");
        foreignUserDNTemplate =
                config.getOrDefault(LDAP_FOREIGN_USER_DN_TEMPLATE, "cn=%s,ou=%s,ou=ForeignUsers,dc=test");
        foreignDomainDNTemplate =
                config.getOrDefault(LDAP_FOREIGN_DOMAIN_DN_TEMPLATE, "ou=%s,ou=ForeignUsers,dc=test");

        //--------------------------------------------------------------------------
        // -- Archive attributes --
        //--------------------------------------------------------------------------
        systemNameAttribute =
                config.getOrDefault(LDAP_SYSTEM_NAME_ATTRIBUTE, "ou");

        //--------------------------------------------------------------------------
        // -- Global group attributes --
        //--------------------------------------------------------------------------
        groupIdAttribute =
                config.getOrDefault(LDAP_GROUP_ID, "ou");
        groupDescriptionAttribute =
                config.getOrDefault(LDAP_GROUP_DESCRIPTION, "description");

        //--------------------------------------------------------------------------
        // -- Subcontexts and search filters (within subcontexts) --
        //--------------------------------------------------------------------------
        usersContext =
                config.getOrDefault(LDAP_USERS_CONTEXT, "ou=Users,dc=test");
        userSearchFilter =
                config.getOrDefault(LDAP_USER_SEARCH_FILTER, "(cn=*)");
        groupsContext =
                config.getOrDefault(LDAP_GROUPS_CONTEXT, "ou=Groups,dc=test");
        groupSearchFilter =
                config.getOrDefault(LDAP_GROUP_SEARCH_FILTER, "(ou=*)");
        systemsContext =
                config.getOrDefault(LDAP_SYSTEMS_CONTEXT, "ou=Systems,dc=test");
        systemSearchFilter =
                config.getOrDefault(LDAP_SYSTEM_SEARCH_FILTER, "(ou=*)");

        //--------------------------------------------------------------------------
        // -- Search filter for finding roles in a specific archive --
        //--------------------------------------------------------------------------
        roleSearchFilter = config.getOrDefault(LDAP_ROLE_SEARCH_FILTER, "(ou=*)");
    }

    /**
     * Find object by its distinguished name (regardless of objectClass)
     * <p/>
     * @param dn some distinguished name
     * @return The distinguished name (DN) of the object if user exists in LDAP, null otherwise
     */
    public String findObjectByDn(final String dn) throws ConfigurationException, DirectoryException {
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry obj = adapter.findObject(req);
        if (null != obj) {
            // Return the distinguished name of the object
            return obj.getDn().toString();
        }
        return null;
    }

    /**
     * Creates a system entry in the directory.
     * <p/>
     * It is the responsibility of the caller to verify that a system object does not already
     * exist.
     */
    public String createSystem(final String systemName) throws ConfigurationException, DirectoryException {

        String _systemDn = LdapAdapter.compose(systemDNTemplate, systemName);

        try {
            Dn systemDn = new Dn(_systemDn);

            DefaultEntry systemEntry = new DefaultEntry(systemDn);
            systemEntry.add("objectclass", "organizationalUnit");
            systemEntry.add("ou", systemName);

            adapter.createObject(systemEntry);
        }
        catch (LdapInvalidDnException e) {
            String info = "Invalid system DN: " + _systemDn;
            throw new ConfigurationException(info);
        }
        catch (LdapException e) {
            String info = "Could not assemble a new entry for system " + systemName;
            info += ": " + e.getMessage();
            throw new DirectoryWriteException(info, e);
        }

        return _systemDn; // If all OK
    }


    /**
     * Assigns a user, identified by an id, to a role.
     */
    public String assignUserToRole(final String userId, final String roleId, final String systemName) throws InvalidParameterException, ConfigurationException, DirectoryException {

        final String _userDn = LdapAdapter.compose(userDNTemplate, userId);
        if (null == findObjectByDn(_userDn)) {
            String info = "The specified user is unknown to the system: \"" + userId + "\" (" + _userDn + ")";
            throw new InvalidParameterException(info);
        }

        // ou=Roles,ou=<systemName>,ou=Systems,dc=test
        String _rolesDn = LdapAdapter.compose(rolesDNTemplate, systemName);
        if (null == findObjectByDn(_rolesDn)) {
            try {
                Dn rolesDn = new Dn(_rolesDn);

                DefaultEntry rolesEntry = new DefaultEntry(rolesDn);
                rolesEntry.add("objectclass", "organizationalUnit");
                rolesEntry.add("ou", "Roles");

                adapter.createObject(rolesEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid roles DN: " + _rolesDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not create roles base entry in system " + systemName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        // ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,dc=test
        String _roleDn = LdapAdapter.compose(roleDNTemplate, roleId, systemName);
        if (null == findObjectByDn(_roleDn)) {
            try {
                Dn roleDn = new Dn(_roleDn);

                DefaultEntry roleEntry = new DefaultEntry(roleDn);
                roleEntry.add("objectclass", "organizationalUnit");
                roleEntry.add(groupIdAttribute, roleId);

                adapter.createObject(roleEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role DN: " + _roleDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new entry for role " + roleId + " in system " + systemName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        // cn=<userId>,ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,dc=test
        final String _participationDn = LdapAdapter.compose(userInRoleDNTemplate, userId, roleId, systemName);
        if (null == findObjectByDn(_participationDn)) {
            try {
                Dn participationDn = new Dn(_participationDn);

                DefaultEntry participationEntry = new DefaultEntry(participationDn);
                participationEntry.add("objectclass", membershipObjectClass);
                participationEntry.add("cn", userId);
                participationEntry.add(membershipAttribute, _userDn);
                adapter.createObject(participationEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role participation DN: " + _participationDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new participation entry for user " + userId + " in role " + roleId + " in system " + systemName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }
        return _participationDn; // If all OK
    }

    private boolean participationExistsUnderRole(final String roleDn, final String principalId, final String principalDn)
            throws ConfigurationException, DirectoryException {

        String filter = LdapAdapter.compose(
                "(&(objectClass=%s)(cn=%s)(%s=%s))",
                membershipObjectClass, principalId, membershipAttribute, principalDn
        );
        SearchRequest req = adapter.shallowSearchWithFilter(roleDn, filter, "cn", membershipAttribute);
        return adapter.findObject(req) != null;
    }

    /**
     * Assigns a group, identified by an id, to a role.
     */
    public String assignGroupToRole(final String groupId, final String roleId, final String systemName) throws InvalidParameterException, ConfigurationException, DirectoryException {
        final String _groupDn = LdapAdapter.compose(groupDNTemplate, groupId);
        if (null == findObjectByDn(_groupDn)) {
            String info = "The specified global group is unknown to the system: \"" + groupId + "\" (" + _groupDn + ")";
            throw new InvalidParameterException(info);
        }

        // Ensure Roles base exists
        // default: ou=Roles,ou=<systemName>,ou=Systems,dc=test
        String _rolesDn = LdapAdapter.compose(rolesDNTemplate, systemName);
        if (null == findObjectByDn(_rolesDn)) {
            try {
                Dn rolesDn = new Dn(_rolesDn);
                DefaultEntry rolesEntry = new DefaultEntry(rolesDn);
                rolesEntry.add("objectclass", "organizationalUnit");
                rolesEntry.add("ou", "Roles");
                adapter.createObject(rolesEntry);
            }
            catch (LdapInvalidDnException e) {
                throw new ConfigurationException("Invalid roles DN: " + _rolesDn);
            }
            catch (LdapException e) {
                String info = "Could not create roles base entry in system " + systemName + ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        // Ensure Role container exists
        // default: ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,dc=test
        String _roleDn = LdapAdapter.compose(roleDNTemplate, roleId, systemName);
        if (null == findObjectByDn(_roleDn)) {
            try {
                Dn roleDn = new Dn(_roleDn);
                DefaultEntry roleEntry = new DefaultEntry(roleDn);
                roleEntry.add("objectclass", "organizationalUnit");
                roleEntry.add(groupIdAttribute, roleId);
                adapter.createObject(roleEntry);
            }
            catch (LdapInvalidDnException e) {
                throw new ConfigurationException("Invalid role DN: " + _roleDn);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new entry for role " + roleId + " in system " + systemName + ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        final String _participationDn = LdapAdapter.compose(groupInRoleDNTemplate, groupId, roleId, systemName);
        if (!participationExistsUnderRole(_roleDn, groupId, _groupDn)) {
            // Create ONE participation entry (cn-based) for group -> role
            // default: cn=<groupId>,ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,dc=test
            if (null == findObjectByDn(_participationDn)) {
                try {
                    Dn participationDn = new Dn(_participationDn);
                    DefaultEntry participationEntry = new DefaultEntry(participationDn);
                    participationEntry.add("objectclass", membershipObjectClass);
                    participationEntry.add("cn", groupId);
                    participationEntry.add(membershipAttribute, _groupDn); // group (DN) participates in role
                    adapter.createObject(participationEntry);
                }
                catch (LdapInvalidDnException e) {
                    throw new ConfigurationException("Invalid role participation DN: " + _participationDn);
                }
                catch (LdapException e) {
                    String info = "Could not assemble a new participation entry for group " + groupId
                            + " in role " + roleId + " in system " + systemName + ": " + e.getMessage();
                    throw new DirectoryWriteException(info, e);
                }
            }
        }

        return _participationDn; // If all OK
    }

    /**
     * Does the named user exist in the directory?
     * <p/>
     * @param userId user ID (value associated with the 'cn' or 'uid' attributes)
     * @return The distinguished name (DN) of the user if user exists in LDAP, null otherwise
     */
    public String findUserDn(final String userId) throws ConfigurationException, DirectoryException {
        final String filter = LdapAdapter.compose("(&(objectClass=%s)(%s=%s))", userObjectClass, userIdAttribute, userId);
        SearchRequest req = adapter.shallowSearchWithFilter(usersContext, filter, userIdAttribute);

        Entry user = adapter.findObject(req);
        if (null != user) {
            // Return the distinguished name of the user
            return user.getDn().toString();
        }
        return null;
    }

    /**
     * Checks whether the named global group exists or not.
     * <p/>
     * @param groupName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean globalGroupExists(final String groupName) throws ConfigurationException, DirectoryException {
        String dn = LdapAdapter.compose(groupDNTemplate, groupName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry group = adapter.findObject(req);
        return null != group;
    }

    /**
     * Checks whether the named system exists or not.
     * <p/>
     * @param systemName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean systemExists(final String systemName) throws ConfigurationException, DirectoryException {
        String dn = LdapAdapter.compose(systemDNTemplate, systemName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry system = adapter.findObject(req);
        return null != system;
    }

    /**
     * Checks if a named user is member of a named (global) group.
     * <p/>
     * @param userId
     * @param groupName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean isMemberOfGlobalGroup(final String userId, final String groupName) throws ConfigurationException, DirectoryException {

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Compose a DN for a user groupMember and try to locate it.
        //------------------------------------------------------------------------
        String dn;
        if (groupName.startsWith("ou=")) {
            // Whole ou= stored in database
            dn = LdapAdapter.compose("cn=%s,%s", userId, groupName);
        } else {
            // "cn=<userName>,ou=<groupName>,ou=Groups,dc=test"
            dn = LdapAdapter.compose(userInGroupDNTemplate, userId, groupName);
        }
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");
        Entry user = adapter.findObject(req);
        return null != user;
    }




    public Collection<String> getUsersInGlobalGroup(final String groupName) throws ConfigurationException, DirectoryException {
        Collection<String> users = new LinkedList<>();

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------
        String dn = LdapAdapter.compose(groupDNTemplate, groupName);
        final String filter = LdapAdapter.compose("(objectClass=%s)", membershipObjectClass);
        SearchRequest req = adapter.shallowSearchWithFilter(dn, filter, "*");
        Collection<Entry> _users = adapter.findObjects(req);
        for (Entry user : _users) {
            try {
                Attribute a = user.get("cn");
                if (null != a) {
                    String cn = a.getString();
                    users.add(cn); // userId
                }

                a = user.get(membershipAttribute);
                if (null != a) {
                    String memberObject = a.getString();
                    // users.add(memberObject); // userDN
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "User in group entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return users;
    }

    public Collection<String> getUsersInRole(final String roleName, final String systemName) throws ConfigurationException, DirectoryException {
        Collection<String> users = new LinkedList<>();

        //------------------------------------------------------------------------
        // Roles live under "ou=<roleName>, ou=Roles, ou=<systemName>, ou=Systems, dc=test"
        // Strategy: Get all entries directly thereunder.
        // BEWARE: There may be groups entries there as well!
        //------------------------------------------------------------------------

        String dn = LdapAdapter.compose(roleDNTemplate, roleName, systemName);
        final String filter = LdapAdapter.compose("(objectClass=%s)", membershipObjectClass);
        SearchRequest req = adapter.shallowSearchWithFilter(dn, filter, "*");
        Collection<Entry> _users = adapter.findObjects(req);
        for (Entry user : _users) {
            try {
                Attribute a = user.get("cn");
                if (null != a) {
                    String cn = a.getString();
                    users.add(cn); // userId
                }

                a = user.get(membershipAttribute);
                if (null != a) {
                    String memberObject = a.getString();
                    // users.add(memberObject); // userDN
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "User in role entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return users;
    }


    /**
     * Returns the groupIds in the searched LDAP context
     */
    public Collection<String> getGlobalGroups() throws ConfigurationException, DirectoryException {
        Collection<String> groups = new LinkedList<>();

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------

        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(groupsContext, filter, "*");
        Collection<Entry> _groups = adapter.findObjects(req);
        for (Entry group : _groups) {
            String dn = group.getDn().toString();

            try {
                Attribute a = group.get("ou");
                if (null != a) {
                    String cn = a.getString();
                    groups.add(cn); // groupId
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "Group in group entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return groups;
    }

    public Collection<String> getSystems() throws ConfigurationException, DirectoryException {
        Collection<String> systems = new LinkedList<>();

        //------------------------------------------------------------------------
        // Systems live under "ou=Systems, dc=test".
        // Strategy: Get all entries under "ou=Systems, dc=test"
        //------------------------------------------------------------------------
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(systemsContext, filter, "*");
        Collection<Entry> _systems = adapter.findObjects(req);
        for (Entry system : _systems) {
            systems.add(adapter.getSimpleName(system.getDn()));
        }

        return systems;
    }

    /**
     * Returns the groupids in the searched LDAP context
     *
     * @return a Collection of roles
     */
    public Collection<String> getRolesInSystem(final String systemName) throws ConfigurationException, DirectoryException{
        Collection<String> roles = new LinkedList<>();

        //------------------------------------------------------------------------
        // Roles of an systems live under "ou=Roles, ou=<systemName>, ou=Systems, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------
        final String base = LdapAdapter.compose(rolesDNTemplate, systemName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(base, filter, "*");
        Collection<Entry> _roles = adapter.findObjects(req);
        for (Entry role : _roles) {
            roles.add(adapter.getSimpleName(role.getDn()));
        }

        return roles;
    }


    /*
     *
     */
    private void groupsAndRolesAnalysis(
            final String userId,
            final String userDn,
            final HashSet<String> globalGroups,
            Hashtable<String, HashSet<String>> roles
    ) throws ConfigurationException, DirectoryException {

        /* --------------------------------------------------------------------------------
         * Determine list of global group memberships
         *
         * Membership is determined by a having a groupMember object under the
         * global group with memberObject = user DN.
         *
         * The result is a list of "simple" group names (and not DNs to these groups)
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing global group memberships of user \"{}\" ({})", userId, userDn);

        final String filter = LdapAdapter.compose("(&(objectClass=%s)(%s=%s))", membershipObjectClass, membershipAttribute, userDn);

        SearchRequest req = adapter.deepSearchWithFilter(groupsContext, filter, "*");
        Collection<Entry> memberships = adapter.findObjects(req);

        for (Entry membership : memberships) {
            // From: cn=<userId>, ou=<groupName>, ou=Groups, dc=test
            // To:  {cn=<userId>, ou=<groupName>, ou=Groups, dc=test}
            Rdn[] membershipRdns = membership.getDn().getRdns().toArray(RdnT);

            //
            Rdn groupRdn = membershipRdns[1];
            Value _groupName = groupRdn.getAva().getValue();
            String groupName = _groupName.getString();

            globalGroups.add(groupName);

            log.trace("User \"{}\" ({}) is a member of the global group \"{}\"", userId, userDn, groupName);
        }

        /* --------------------------------------------------------------------------------
         * Determine list of direct role participations for user
         *
         * Direct participation is determined by a having a groupMember object under the
         * global group with memberObject = user DN.
         *
         * The result is a hashtable (hashed on system name) with lists of "simple"
         * role names (and not DNs to these roles).
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing direct role participation of user \"{}\" ({})", userId, userDn);

        req = adapter.deepSearchWithFilter(systemsContext, filter, "*");
        Collection<Entry> participations = adapter.findObjects(req);

        for (Entry participation : participations) {
            // From: cn=<userId>, ou=<roleName>, ou=Roles, ou=<systemName>, ou=Systems, dc=test
            // To:  {cn=<userId>, ou=<roleName>, ou=Roles, ou=<systemName>, ou=Systems, dc=test}
            Rdn[] participationRdns = participation.getDn().getRdns().toArray(RdnT);

            //
            Rdn roleRdn = participationRdns[1];
            Value _roleName = roleRdn.getAva().getValue();
            String roleName = _roleName.getString();

            //
            Rdn systemRdn = participationRdns[3];
            Value _systemName = systemRdn.getAva().getValue();
            String systemName = _systemName.getString();

            //
            HashSet<String> _roles = roles.computeIfAbsent(systemName, k -> new HashSet<>());
            _roles.add(roleName);

            log.trace("User \"{}\" ({}) participates directly in role \"{}\" in system \"{}\"", userId, userDn, roleName, systemName);
        }

        /* --------------------------------------------------------------------------------
         * Determine list of indirect role participations for groups that user is part of
         *
         * Indirect participation is determined by a having a groupMember object under the
         * global group with memberObject = group DN (and not the user DN). Since we haven't
         * stored the group DN (from above), we will recreate these using groupDNTemplate.
         *
         * The result is a hashtable (hashed on system name) with lists of "simple"
         * role names (and not DNs to these roles).
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing indirect role participation user \"{}\" ({})", userId, userDn);

        int numberOfGroups = globalGroups.size();
        if (numberOfGroups > 0) {

            StringBuilder groupFilter = new StringBuilder("(&(objectClass=").append(membershipObjectClass).append(")");
            if (numberOfGroups > 1) {
                groupFilter.append("(|");
            }
            for (String groupId : globalGroups) {
                log.trace("Looking for group membership \"{}\" in roles", groupId);
                String groupDn = LdapAdapter.compose(groupDNTemplate, groupId);
                groupFilter.append("(").append(membershipAttribute).append("=").append(groupDn).append(")");
            }
            if (numberOfGroups > 1) {
                groupFilter.append(")");
            }
            groupFilter.append(")");

            log.trace("Searching from \"{}\" using filter {}", systemsContext, groupFilter);

            req = adapter.deepSearchWithFilter(systemsContext, groupFilter.toString(), "*");
            participations = adapter.findObjects(req);

            for (Entry participation : participations) {
                // From: cn=<groupId>, ou=<roleName>, ou=Roles, ou=<systemName>, ou=Systems, dc=test
                // To:  {cn=<groupId>, ou=<roleName>, ou=Roles, ou=<systemName>, ou=Systems, dc=test}
                Rdn[] participationRdns = participation.getDn().getRdns().toArray(RdnT);

                //
                Rdn roleRdn = participationRdns[1];
                Value _roleName = roleRdn.getAva().getValue();
                String roleName = _roleName.getString();

                //
                Rdn systemRdn = participationRdns[3];
                Value _systemName = systemRdn.getAva().getValue();
                String systemName = _systemName.getString();

                //
                HashSet<String> _roles = roles.computeIfAbsent(systemName, k -> new HashSet<>());
                _roles.add(roleName);

                log.trace("User \"{}\" ({}) participates indirectly in role \"{}\" in system \"{}\" through a group membership", userId, userDn, roleName, systemName);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("Analysis ready");
        }
    }

    /**
     * Computes effective roles for a user, including roles granted via global groups.
     *
     * @param userId the user identifier
     * @return roles per system
     */
    public Hashtable<String, HashSet<String>> groupsAndRolesAnalysis(final String userId)
            throws ConfigurationException, DirectoryException, InvalidParameterException {
        String userDn = findUserDn(userId);
        if (null == userDn) {
            String info = "The specified user is unknown to the system: \"" + userId + "\"";
            throw new InvalidParameterException(info);
        }

        HashSet<String> globalGroups = new HashSet<>();
        Hashtable<String, HashSet<String>> roles = new Hashtable<>();
        groupsAndRolesAnalysis(userId, userDn, globalGroups, roles);
        return roles;
    }
}

