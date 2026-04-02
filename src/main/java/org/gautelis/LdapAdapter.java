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
import org.apache.directory.api.ldap.model.filter.FilterEncoder;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.ldap.client.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;


/**
 * Manages a connection to an LDAP directory service and executes
 * queries and updates through it.
 */
public class LdapAdapter implements AutoCloseable {
    static final Logger log = LoggerFactory.getLogger(LdapAdapter.class);

    interface PooledExecutor {
        <T> T withConnection(ConnectionOperation<T> operation) throws DirectoryException;
        void close();
    }

    interface ConnectionManager {
        LdapConnection getConnection() throws Exception;
        void releaseConnection(LdapConnection connection) throws Exception;
        void close();
    }

    interface ConnectionOperation<T> {
        T execute(LdapConnection connection) throws Exception;
    }

    private static final class PoolConnectionManager implements ConnectionManager {
        private final LdapConnectionPool pool;

        private PoolConnectionManager(LdapConnectionPool pool) {
            this.pool = pool;
        }

        @Override
        public LdapConnection getConnection() throws Exception {
            return pool.getConnection();
        }

        @Override
        public void releaseConnection(LdapConnection connection) throws Exception {
            pool.releaseConnection(connection);
        }

        @Override
        public void close() {
            pool.close();
        }
    }

    private static final class ManagedPooledExecutor implements PooledExecutor {
        private final ConnectionManager connectionManager;

        private ManagedPooledExecutor(ConnectionManager connectionManager) {
            this.connectionManager = connectionManager;
        }

        @Override
        public <T> T withConnection(ConnectionOperation<T> operation) throws DirectoryException {
            LdapConnection connection = null;
            DirectoryException pending = null;
            T result = null;
            try {
                connection = connectionManager.getConnection();
                result = operation.execute(connection);
            }
            catch (DirectoryException e) {
                pending = e;
            }
            catch (Exception e) {
                pending = mapException(e);
            }
            finally {
                if (connection != null) {
                    releaseConnection(connection, pending);
                }
            }
            if (pending != null) {
                throw pending;
            }
            return result;
        }

        @Override
        public void close() {
            connectionManager.close();
        }

        private void releaseConnection(LdapConnection connection, DirectoryException pending) throws DirectoryException {
            try {
                connectionManager.releaseConnection(connection);
            }
            catch (Exception e) {
                String info = "Could not release connection back to pool: " + e.getMessage();
                DirectoryConnectionException releaseFailure = new DirectoryConnectionException(info, e);
                if (pending != null) {
                    pending.addSuppressed(releaseFailure);
                    throw pending;
                }
                throw releaseFailure;
            }
        }

        private DirectoryException mapException(Exception e) {
            if (e instanceof LdapInvalidDnException invalidDn) {
                Dn dn = invalidDn.getResolvedDn();
                String info = "Invalid DN: " + (dn != null ? dn.toString() : invalidDn.getMessage());
                return new DirectoryWriteException(info, invalidDn);
            }
            if (e instanceof LdapSchemaViolationException schemaViolation) {
                String info = "Could not create object since it violates the schema: ";
                Dn dn = schemaViolation.getResolvedDn();
                if (dn != null && !dn.getName().isEmpty()) {
                    info += "dn=\"" + dn + "\", ";
                }
                ResultCodeEnum rc = schemaViolation.getResultCode();
                info += "result-code=" + rc.getResultCode() + " (" + rc.getMessage() + "): ";
                Throwable cause = schemaViolation.getCause();
                info += Objects.requireNonNullElse(cause, schemaViolation).getMessage();
                return new DirectoryWriteException(info, schemaViolation);
            }
            if (e instanceof LdapException ldapException) {
                return new DirectoryException(ldapException.getMessage(), ldapException) { };
            }
            String info = e.getMessage();
            return new DirectoryException(info, e) { };
        }
    }

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

    /**
     * Maximum number of pooled LDAP connections.
     */
    public static final String LDAP_POOL_MAX_TOTAL = "LDAP_POOL_MAX_TOTAL";

    /**
     * Maximum number of idle pooled LDAP connections.
     */
    public static final String LDAP_POOL_MAX_IDLE = "LDAP_POOL_MAX_IDLE";

    /**
     * Minimum number of idle pooled LDAP connections.
     */
    public static final String LDAP_POOL_MIN_IDLE = "LDAP_POOL_MIN_IDLE";

    /**
     * Whether to validate pooled connections when borrowed.
     */
    public static final String LDAP_POOL_TEST_ON_BORROW = "LDAP_POOL_TEST_ON_BORROW";

    /**
     * Whether callers should wait when the pool is exhausted.
     */
    public static final String LDAP_POOL_BLOCK_WHEN_EXHAUSTED = "LDAP_POOL_BLOCK_WHEN_EXHAUSTED";

    /**
     * Maximum time to wait for a pooled connection in milliseconds.
     */
    public static final String LDAP_POOL_MAX_WAIT_MILLIS = "LDAP_POOL_MAX_WAIT_MILLIS";

    //
    private final PooledExecutor executor;
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
        if (null == _host || _host.isEmpty()) {
            // Not likely to happen, given that we have a default value
            throw new ConfigurationException("No LDAP server host was provided");
        }
        host = _host;
        ldapConfig.setLdapHost(_host);

        // LDAP server port
        String _port = config.getOrDefault(LDAP_PORT, "389");
        if (null == _port || _port.isEmpty()) {
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
        LdapConnectionPool pool = new LdapConnectionPool( factory );
        configurePool(pool, config);
        this.executor = new ManagedPooledExecutor(new PoolConnectionManager(pool));
    }

    LdapAdapter(ConnectionManager connectionManager) {
        this.executor = new ManagedPooledExecutor(connectionManager);
        this.host = "localhost";
        this.port = 389;
    }

    LdapAdapter(PooledExecutor executor) {
        this.executor = executor;
        this.host = "localhost";
        this.port = 389;
    }

    public void close() {
        if (null != executor) {
            executor.close();
        }
    }

    private void configurePool(LdapConnectionPool pool, Map<String, String> config) throws ConfigurationException {
        int maxTotal = parseInteger(config, LDAP_POOL_MAX_TOTAL, 8);
        int maxIdle = parseInteger(config, LDAP_POOL_MAX_IDLE, 8);
        int minIdle = parseInteger(config, LDAP_POOL_MIN_IDLE, 0);
        long maxWaitMillis = parseLong(config, LDAP_POOL_MAX_WAIT_MILLIS, 30000L);
        boolean testOnBorrow = parseBoolean(config, LDAP_POOL_TEST_ON_BORROW, true);
        boolean blockWhenExhausted = parseBoolean(config, LDAP_POOL_BLOCK_WHEN_EXHAUSTED, true);

        if (maxTotal <= 0) {
            throw new ConfigurationException("Illegal LDAP pool max total: " + maxTotal);
        }
        if (maxIdle < 0) {
            throw new ConfigurationException("Illegal LDAP pool max idle: " + maxIdle);
        }
        if (minIdle < 0) {
            throw new ConfigurationException("Illegal LDAP pool min idle: " + minIdle);
        }
        if (minIdle > maxIdle) {
            throw new ConfigurationException("Illegal LDAP pool idle bounds: min idle exceeds max idle");
        }
        if (maxIdle > maxTotal) {
            throw new ConfigurationException("Illegal LDAP pool idle bounds: max idle exceeds max total");
        }
        if (maxWaitMillis < 0) {
            throw new ConfigurationException("Illegal LDAP pool max wait millis: " + maxWaitMillis);
        }

        pool.setMaxTotal(maxTotal);
        pool.setMaxIdle(maxIdle);
        pool.setMinIdle(minIdle);
        pool.setTestOnBorrow(testOnBorrow);
        pool.setBlockWhenExhausted(blockWhenExhausted);
        pool.setMaxWaitMillis(maxWaitMillis);
    }

    private static int parseInteger(Map<String, String> config, String key, int defaultValue) throws ConfigurationException {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        }
        catch (NumberFormatException e) {
            throw new ConfigurationException("Illegal integer value for " + key + ": " + value);
        }
    }

    private static long parseLong(Map<String, String> config, String key, long defaultValue) throws ConfigurationException {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(value);
        }
        catch (NumberFormatException e) {
            throw new ConfigurationException("Illegal long value for " + key + ": " + value);
        }
    }

    private static boolean parseBoolean(Map<String, String> config, String key, boolean defaultValue) throws ConfigurationException {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        if ("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value)) {
            return Boolean.parseBoolean(value);
        }
        throw new ConfigurationException("Illegal boolean value for " + key + ": " + value);
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
    interface Create {
        void createUsing(final LdapConnection connection) throws LdapException;
    }

    /**
     * Creates an object.
     */
    public void createObject(final DefaultEntry entry) throws DirectoryException {
        executeWrite("Could not create object in directory", connection -> {
            connection.add(entry);
            return null;
        });
    }

    /**
     * An LDAP alteration functor
     */
    interface Alter {
        ModifyResponse alterUsing(final LdapConnection connection) throws LdapException;
    }

    /**
     * Create an object.
     * <p/>
     * @throws DirectoryException
     */
    private void alterObject(Alter call) throws DirectoryException {
        executeWrite("Could not alter object in directory", connection -> call.alterUsing(connection));
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
    interface Query {
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
        return executeRead("Could not find object in directory", connection -> {
            try (SearchCursor cursor = call.queryUsing(connection)) {
                if (cursor.next()) {
                    if (cursor.isEntry())
                        return ((SearchResultEntry) cursor.get()).getEntry();
                }
                return null; // None found
            }
        });
    }

    /**
     * Find all objects based on query.
     * <p/>
     * @param call
     * @return
     * @throws DirectoryException
     */
    private Collection<Entry> findObjects(final Query call) throws DirectoryException {
        return executeRead("Could not find objects in directory", connection -> {
            Collection<Entry> entries = new LinkedList<>();
            try (SearchCursor cursor = call.queryUsing(connection)) {
                while (cursor.next()) {
                    if (cursor.isEntry()) {
                        Entry entry = ((SearchResultEntry) cursor.get()).getEntry();
                        entries.add(entry);
                    }
                }
            }
            return entries;
        });
    }

    private <T> T executeRead(String failureMessage, ConnectionOperation<T> operation) throws DirectoryException {
        try {
            return executor.withConnection(operation);
        }
        catch (DirectoryReadException e) {
            throw e;
        }
        catch (DirectoryConnectionException e) {
            throw e;
        }
        catch (DirectoryException e) {
            DirectoryReadException wrapped = new DirectoryReadException(failureMessage + ": " + e.getMessage(), e);
            for (Throwable suppressed : e.getSuppressed()) {
                wrapped.addSuppressed(suppressed);
            }
            throw wrapped;
        }
    }

    private <T> T executeWrite(String failureMessage, ConnectionOperation<T> operation) throws DirectoryException {
        try {
            return executor.withConnection(operation);
        }
        catch (DirectoryWriteException e) {
            throw e;
        }
        catch (DirectoryConnectionException e) {
            throw e;
        }
        catch (DirectoryException e) {
            DirectoryWriteException wrapped = new DirectoryWriteException(failureMessage + ": " + e.getMessage(), e);
            for (Throwable suppressed : e.getSuppressed()) {
                wrapped.addSuppressed(suppressed);
            }
            throw wrapped;
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

        if (null == template || template.isEmpty()) {
            String info = "No distinguished name template was provided";
            throw new ConfigurationException(info);
        }

        StringBuilder dn = new StringBuilder(template);
        for (String component : components) {
            int idx = dn.indexOf("%s");
            if (idx >= 0) {
                // substitute the component for this "%s"
                dn.replace(idx, idx + /* length("%s") */ 2, escapeDnValue(component));
            }
            else {
                String info = "Mismatch between template \"" + template + "\" and the number of provided components: ";
                info += "There are more components than %s markers in the template";
                log.error(info, new Exception("A synthetic exception to gain stack trace"));
                throw new ConfigurationException(info);
            }
        }

        if (dn.indexOf("%s") >= 0) {
            String info = "Mismatch between template \"" + template + "\" and the number of provided components: ";
            info += "There are fewer components than %s markers in the template";
            log.error(info, new Exception("A synthetic exception to gain stack trace"));
            throw new ConfigurationException(info);
        }

        return dn.toString();
    }

    public static String escapeDnValue(String value) {
        return Rdn.escapeValue(value);
    }

    public static String escapeFilterValue(String value) {
        return FilterEncoder.encodeFilterValue(value);
    }
}

