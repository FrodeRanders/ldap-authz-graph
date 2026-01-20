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

import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaViolationException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;


/**
 * Manages a connection to an LDAP directory service and executes
 * queries and updates through it.
 */
public class LdapAdapter implements AutoCloseable {
    static final Logger log = LoggerFactory.getLogger(LdapAdapter.class);

    /**
     * LDAP server host name (key).
     * <p/>
     * A typical value is
     * <I>"localhost"</I>
     */
    public static final String LDAP_HOST = "LDAP_HOST";

    /**
     * LDAP server host port (key).
     * <p/>
     * A typical value is
     * <I>"389"</I>
     */
    public static final String LDAP_PORT = "LDAP_PORT";

    /**
     * LDAP authentication method (key)
     * <p/>
     * A typical value is
     * <I>"simple"</I>
     */
    public static final String LDAP_AUTHENTICATION_METHOD = "LDAP_AUTH_METHOD";

    /**
     * LDAP (protocol) version (key)
     * <p/>
     * A typical value is
     * <I>"3"</I>
     */
    public static final String LDAP_VERSION = "LDAP_VERSION";

    /**
     * LDAP reader DN (key).
     * <p/>
     * A typical value is
     * <I>"uid=Reader,dc=something"</I>
     */
    public static final String LDAP_READER_DN = "LDAP_READER_DN";

    /**
     * LDAP reader credentials (key).
     */
    public static final String LDAP_READER_CREDENTIALS = "LDAP_READER_CREDENTIALS";

    //
    private final LdapConnectionPool pool;
    private final String host;
    private final int port;

    /**
     * Creates an LDAP adapter for communicating with a directory service.
     * <p/>
     * @param config the configuration
     * @throws ConfigurationException if there are configuration errors (missing information)
     */
    public LdapAdapter(Map<String, String> config) throws ConfigurationException {

        LdapConnectionConfig ldapConfig = new LdapConnectionConfig();

        // LDAP server hostname
        String _host = config.getOrDefault(LDAP_HOST, "localhost");
        if (null == _host || _host.length() == 0) {
            // Not likely to happen, given that we have a default value
            throw new ConfigurationException("No LDAP server host was provided");
        }
        host = _host;
        ldapConfig.setLdapHost(_host);

        // LDAP server port
        String _port = config.getOrDefault(LDAP_PORT, "389");
        if (null == _port || _port.length() == 0) {
            // Not likely to happen, given that we have a default value
            String info = "No LDAP server port was provided";
            throw new ConfigurationException(info);
        }

        try {
            port = Integer.parseInt(_port);
            ldapConfig.setLdapPort(port);
        }
        catch (NumberFormatException nfe) {
            String info = "Illegal LDAP port \"" + _port + "\": " + nfe.getMessage();
            throw new ConfigurationException(info);
        }

        // Manager DN
        String _manager = config.get(LDAP_READER_DN); // no default
        if (null == _manager || _manager.isEmpty()) {
            throw new ConfigurationException("No reader DN was provided");
        }
        ldapConfig.setName(_manager);

        // Manager password
        String _credentials = config.get(LDAP_READER_CREDENTIALS); // no default
        if (null == _credentials || _credentials.isEmpty()) {
            throw new ConfigurationException("No reader credentials was provided");
        }
        ldapConfig.setCredentials(_credentials);

        //
        DefaultPoolableLdapConnectionFactory factory = new DefaultPoolableLdapConnectionFactory( ldapConfig );
        this.pool = new LdapConnectionPool( factory );
        pool.setTestOnBorrow( true );
    }

    public void close() {
        if (null != pool) {
            pool.close();
        }
    }

    /**
     * Retrieves the "simple" name "a" from the distinguished name
     * "ou=a, ou=b, dc=c"
     * @param dn
     * @return
     */
    public String getSimpleName(Dn dn) {
        Value name = dn.getRdn().getAva().getValue();
        return name.getString();
    }

    /**
     * An LDAP creation functor
     */
    private interface Create {
        void createUsing(final LdapConnection connection) throws LdapException;
    }

    /**
     * Create an object.
     * <p/>
     * @throws DirectoryException
     */
    private Entry createObject(Create call) throws DirectoryException {
        LdapConnection connection = null;
        try {
            connection = pool.getConnection();
            call.createUsing(connection);
        }
        catch (LdapInvalidDnException e) {
            Dn dn = e.getResolvedDn();
            String info = "Invalid DN: " + dn.toString();
            throw new DirectoryWriteException(info, e);
        }
        catch (LdapSchemaViolationException e) {
            String info = "Could not create object since it violates the schema: ";
            Dn dn = e.getResolvedDn();
            if (null != dn && dn.getName().length() > 0) {
                info += "dn=\"" + dn.toString() + "\", ";
            }
            ResultCodeEnum rc = e.getResultCode();
            info += "result-code=" + rc.getResultCode() + " (" + rc.getMessage() + "): ";
            Throwable cause = e.getCause();
            if (null != cause) {
                info += cause.getMessage();
            } else {
                info += e.getMessage();
            }
            throw new DirectoryWriteException(info, e);
        }
        catch (Throwable t) {
            String info = "Could not create object in directory: " + t.getMessage();
            throw new DirectoryWriteException(info, t);
        }
        finally {
            if (null != connection) {
                try { pool.releaseConnection(connection); }
                catch (Exception e) {
                    String info = "Could not release connection back to pool: " + e.getMessage();
                    throw new DirectoryConnectionException(info, e);
                }
            }
        }
        return null;
    }

    /**
     * Creates an object.
     */
    public void createObject(final DefaultEntry entry) throws DirectoryException {
        createObject(connection -> connection.add(entry));
    }

    /**
     * An LDAP alteration functor
     */
    private interface Alter {
        ModifyResponse alterUsing(final LdapConnection connection) throws LdapException;
    }

    /**
     * Create an object.
     * <p/>
     * @throws DirectoryException
     */
    private void alterObject(Alter call) throws DirectoryException {
        LdapConnection connection = null;
        try {
            connection = pool.getConnection();
            ModifyResponse response = call.alterUsing(connection);
        }
        catch (Throwable t) {
            String info = "Could not alter object in directory: " + t.getMessage();
            throw new DirectoryWriteException(info, t);
        }
        finally {
            if (null != connection) {
                try { pool.releaseConnection(connection); }
                catch (Exception e) {
                    String info = "Could not release connection back to pool: " + e.getMessage();
                    throw new DirectoryConnectionException(info, e);
                }
            }
        }
    }

    /**
     * Alters an object.
     */
    public void alterObject(final ModifyRequest request) throws DirectoryException {
        alterObject(connection -> connection.modify(request));
    }


    /**
     * An LDAP query functor
     */
    private interface Query {
        SearchCursor queryUsing(final LdapConnection connection) throws LdapException;
    }

    /**
     * Find _one_ object based on query.
     * <p/>
     * @param call
     * @return
     * @throws DirectoryException
     */
    public Entry findObject(final Query call) throws DirectoryException {
        LdapConnection connection = null;
        try {
            connection = pool.getConnection();
            try (SearchCursor cursor = call.queryUsing(connection)) {
                if (cursor.next()) {
                    if (cursor.isEntry())
                        return ((SearchResultEntry) cursor.get()).getEntry();
                }
                return null; // None found
            }
        }
        catch (Throwable t) {
            String info = "Could not find object in directory: " + t.getMessage();
            throw new DirectoryReadException(info, t);
        }
        finally {
            if (null != connection) {
                try { pool.releaseConnection(connection); }
                catch (Exception e) {
                    String info = "Could not release connection back to pool: " + e.getMessage();
                    throw new DirectoryConnectionException(info, e);
                }
            }
        }
    }

    /**
     * Find all objects based on query.
     * <p/>
     * @param call
     * @return
     * @throws DirectoryException
     */
    private Collection<Entry> findObjects(final Query call) throws DirectoryException {
        Collection<Entry> entries = new LinkedList<>();
        LdapConnection connection = null;
        try {
            connection = pool.getConnection();
            SearchCursor cursor = call.queryUsing(connection);
            while (cursor.next()) {
                if (cursor.isEntry()) {
                    Entry entry = ((SearchResultEntry) cursor.get()).getEntry();
                    entries.add(entry);
                }
            }
            return entries;
        }
        catch (Throwable t) {
            String info = "Could not find objects in directory: " + t.getMessage();
            throw new DirectoryReadException(info, t);
        }
        finally {
            if (null != connection) {
                try { pool.releaseConnection(connection); }
                catch (Exception e) {
                    String info = "Could not release connection back to pool: " + e.getMessage();
                    throw new DirectoryConnectionException(info, e);
                }
            }
        }
    }

    /**
     * Finds (first) entry matching search request.
     */
    public Entry findObject(final SearchRequest request) throws DirectoryException {
        return findObject(connection -> connection.search(request));
    }

    /**
     * Finds all entries matching search request.
     */
    public Collection<Entry> findObjects(final SearchRequest request) throws DirectoryException {
        return findObjects(connection -> connection.search(request));
    }


    /**
     * Creates a search request.
     * <p/>
     * @param baseDn
     * @param scope
     * @param filter
     * @param attributes
     * @return
     * @throws ConfigurationException
     */
    public SearchRequest search(
            final String baseDn, final SearchScope scope, final String filter, final String... attributes
    ) throws ConfigurationException {
        SearchRequest req = new SearchRequestImpl();
        try {
            req.setBase(new Dn(baseDn));
            req.setScope(scope);
            if (null != filter) {
                req.setFilter(filter);
            }
            req.addAttributes(attributes);
            req.setTimeLimit(0);
        }
        catch (LdapInvalidDnException lide) {
            String info = "Invalid DN: " + lide.getMessage();
            throw new ConfigurationException(info);
        }
        catch (LdapException le) {
            String info = "Invalid filter: \"" + filter + "\": " + le.getMessage();
            throw new ConfigurationException(info);
        }
        return req;
    }

    /**
     * Creates a search request for a specific object, identified through it's distinguished name.
     * <p/>
     * @param baseDn
     * @param filter
     * @param attributes
     * @return
     * @throws ConfigurationException
     */
    public SearchRequest searchForDn(
            final String baseDn, final String filter, final String... attributes
    ) throws ConfigurationException {
        return search(baseDn, SearchScope.OBJECT, filter, attributes);
    }

    /**
     * Creates a shallow search request for object matching a filter. The search starts at baseDN and
     * descends one level in the directory tree.
     * <p/>
     * @param baseDn
     * @param filter
     * @param attributes
     * @return
     * @throws ConfigurationException
     */
    public SearchRequest shallowSearchWithFilter(
            final String baseDn, final String filter, final String... attributes
    ) throws ConfigurationException {
        return search(baseDn, SearchScope.ONELEVEL, filter, attributes);
    }

    /**
     * Creates a deep search request for object matching a filter. The search starts at baseDN and
     * descends into the whole subtree of the directory tree.
     * <p/>
     * @param baseDn
     * @param filter
     * @param attributes
     * @return
     * @throws ConfigurationException
     */
    public SearchRequest deepSearchWithFilter(
            final String baseDn, final String filter, final String... attributes
    ) throws ConfigurationException {
        return search(baseDn, SearchScope.SUBTREE, filter, attributes);
    }

    /**
     * Composes a string, based on a template and a list of name components.
     * <p/>
     * The template should use "%s" markers in the text - one per name component.
     * <p/>
     * @param template
     * @param components
     * @return
     * @throws ConfigurationException
     */
    public static String compose(String template, String... components) throws ConfigurationException {

        if (null == template || template.length() == 0) {
            String info = "No distinguished name template was provided";
            throw new ConfigurationException(info);
        }

        StringBuilder dn = new StringBuilder(template);
        for (String component : components) {
            int idx = dn.indexOf("%s");
            if (idx >= 0) {
                // substitute the component for this "%s"
                dn.replace(idx, idx + /* length("%s") */ 2, component);
            }
            else {
                String info = "Mismatch between template \"" + template + "\" and the number of provided components: ";
                info += "There are more components than %s markers in the template";
                log.error(info, new Exception("A synthetic exception to gain stack trace"));
                throw new ConfigurationException(info);
            }
        }

        return dn.toString();
    }
}

