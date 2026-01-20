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

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.xdbm.Index;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintWriter;
import java.util.HashSet;


public class LocalLdapServer {
    private static final Logger log = LoggerFactory.getLogger(LocalLdapServer.class);

    private DirectoryService service;
    private LdapServer server;

    public LocalLdapServer() {
    }

    public void start() throws Exception {
        System.out.println("Starting LDAP server and service...");

        if (null != server) {
            return;
        }

        if (null == service) {
            service = initDirectoryService();
        }

        // Start service
        if (!service.isStarted()) {
            try {
                service.startup();

            } catch (Throwable t) {
                Throwable baseCause = getBaseCause(t);
                String info = "Failed to start LDAP service: ";
                String msg = baseCause.getMessage();
                if (null == msg) {
                    info += baseCause.getClass().getName();
                    info += "\n";
                    info += getStacktrace(baseCause);
                } else {
                    info += baseCause.getMessage();
                }

                log.warn(info, baseCause);
                throw new Exception(info, baseCause);
            }
        }



        //-------------------------------------------------------------
        // Objects
        //-------------------------------------------------------------

        // Establish test partition
        Partition partition = addPartition(service, "test", "dc=test");

        // Inject dc=test entry into the test partition (created earlier)
        addEntry("dc=test", entry -> {
            entry.add("objectClass", "top", "domain", "extensibleObject");
            entry.add("dc", "test");
        });

        // User needed in order to search in the directory, not for logging in.
        addEntry("uid=searcher,dc=test", entry -> {
            entry.add("objectClass", "top", "inetOrgPerson", "organizationalPerson", "person");
            entry.add("uid", "searcher");
            entry.add("cn", "Search");
            entry.add("sn", "Account");
            entry.add("description", "An account used for searching the directory (for users)");
            entry.add("userPassword", "{SHA}Ho1UWt+Ko+FWSbW26BviIp7iaGk=".getBytes()); // "notsosecret"
        });

        // --- Global groups ---
        addEntry("ou=Groups,dc=test", entry -> {
            entry.add("objectClass", "organizationalUnit");
            entry.add("ou", "Groups");
        });

        addEntry("ou=Administrators,ou=Groups,dc=test", entry -> {
            entry.add("objectClass", "organizationalUnit");
            entry.add("ou", "Administrators");
        });

        addEntry("ou=Guests,ou=Groups,dc=test", entry -> {
            entry.add("objectClass", "organizationalUnit");
            entry.add("ou", "Guests");
        });

        // --- Users in the system ---
        addEntry("ou=Users,dc=test", entry -> {
            entry.add("objectClass", "organizationalUnit");
            entry.add("ou", "Users");
        });

        addEntry("uid=tester,ou=Users,dc=test", entry -> {
            entry.add("objectClass", "top", "inetOrgPerson", "organizationalPerson", "person");
            entry.add("uid", "tester");
            entry.add("cn", "Test");
            entry.add("sn", "User");
            entry.add("description", "A test user");
            entry.add("userPassword", "{SHA}Ho1UWt+Ko+FWSbW26BviIp7iaGk=".getBytes()); // "notsosecret"
        });

        // --- Systems base ---
        addEntry("ou=Systems,dc=test", entry -> {
            entry.add("objectClass", "organizationalUnit");
            entry.add("ou", "Systems");
        });


        // Index attributes in the partition
        addIndex((JdbmPartition) partition, "objectClass", "ou", "cn", "uid", "member");

        try {
            server = new LdapServer();
            int serverPort = 10389;
            server.setTransports(new TcpTransport(serverPort));
            server.setDirectoryService(service);
            server.start();

        } catch (Throwable t) {
            log.error("Failed to start LDAP server: {}", t.getMessage(), t);
        }
    }

    public void stop() throws Exception {
        System.out.println("Stopping LDAP server and service...");

        if (null != server) {
            server.stop();
            server = null;
        }

        if (null != service && service.isStarted()) {
            service.shutdown();
        }
    }

    private static DirectoryService initDirectoryService() throws Exception {
        // Determine location for LDAP server data (being "$cwd/ldap")
        try {
            // Create service and setup cache service
            DirectoryServiceFactory factory = new DefaultDirectoryServiceFactory();
            factory.init("default");
            DirectoryService s = factory.getDirectoryService();

            // Load schema
            initSchemaPartitionOn(s);

            // Setup system partition
            JdbmPartition systemPartition = new JdbmPartition(s.getSchemaManager(), s.getDnFactory());
            systemPartition.setId("system");
            systemPartition.setPartitionPath(new File(s.getInstanceLayout().getPartitionsDirectory(), systemPartition.getId()).toURI());
            systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
            systemPartition.setSchemaManager(s.getSchemaManager());

            // mandatory to call this method to set the system partition
            // Note: this system partition might be removed from trunk
            s.setSystemPartition(systemPartition);

            //
            String info = s.getInstanceLayout().toString();
            log.info(info);

            return s;

        } catch (Throwable t) {
            Throwable baseCause = getBaseCause(t);
            String info = "Failed to initiate LDAP service: ";
            String msg = baseCause.getMessage();
            if (null == msg) {
                info += baseCause.getClass().getName();
                info += "\n";
                info += getStacktrace(baseCause);
            } else {
                info += baseCause.getMessage();
            }

            log.warn(info, baseCause);
            throw new Exception(info, baseCause);
        }
    }

    private static void initSchemaPartitionOn(DirectoryService s) throws Exception {

        File schemaRepository = new File(s.getInstanceLayout().getPartitionsDirectory(), "schema");

        if (!schemaRepository.exists()) {
            // Extract schema on disk (a brand new one)
            SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(s.getInstanceLayout().getPartitionsDirectory());
            extractor.extractOrCopy();
        }

        //
        SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);

        // Load schema now
        schemaManager.loadAllEnabled();

        java.util.List<Throwable> errors = schemaManager.getErrors();
        if (!errors.isEmpty()) {
            log.error("Error(s) in schema (loaded from {}", schemaRepository.getPath());
            for (Throwable error : errors) {
               log.error(error.getMessage(), error);
            }
            throw new Exception("Could not load initial schemas in embedded LDAP service");
        }

        s.setSchemaManager(schemaManager);

        // Init the LdifPartition with schema
        LdifPartition schemaLdifPartition = new LdifPartition(schemaManager, s.getDnFactory());
        schemaLdifPartition.setPartitionPath(schemaRepository.toURI());

        // The schema partition
        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(schemaLdifPartition);
        s.setSchemaPartition(schemaPartition);
    }

    private static Partition addPartition(DirectoryService s, String partitionId, String partitionDN) throws Exception {

        // Create a new partition
        JdbmPartition partition = new JdbmPartition(s.getSchemaManager(), s.getDnFactory());
        partition.setId(partitionId);
        partition.setPartitionPath(new File(s.getInstanceLayout().getPartitionsDirectory(), partitionId).toURI());
        partition.setSuffixDn(new Dn(partitionDN));
        s.addPartition(partition);

        return partition;
    }

    private static void addIndex(JdbmPartition partition, String... attrs) {
        HashSet<Index<?, String>> indexedAttributes = new HashSet<>();
        for (String attribute : attrs) {
            indexedAttributes.add(new JdbmIndex<String>(attribute, /* with reverse? */ false));
        }
        partition.setIndexedAttributes(indexedAttributes);
    }

    private Entry addEntry(String dn, EntryInitializer initializer) throws Exception {
        log.debug("Adding: {}", dn);
        Dn _dn = new Dn(dn);
        try {
            return service.getAdminSession().lookup(_dn);
        } catch (LdapException le) {
            // No  entry - create one
            Entry entry = service.newEntry(_dn);
            initializer.initialize(entry);
            service.getAdminSession().add(entry);
            return entry;
        }
    }

    interface EntryInitializer {
        void initialize(Entry entry) throws LdapException;
    }

    public static Throwable getBaseCause(Throwable t) {
        Throwable cause = null;
        Throwable c = t.getCause();
        if (null != c) {
            do {
                cause = c;
                c = c.getCause();
            } while (null != c);
        }

        if (null != cause) {
            t = cause;
        }

        return t;
    }

    public static String getStacktrace(Throwable t) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(bytes, true);
        if (null == t) {
            t = new IllegalArgumentException("Synthetic exception for stacktrace");
        }
        t.printStackTrace(writer);
        return bytes.toString();
    }
}
