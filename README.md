# ldap-authz-graph

A lightweight convention for modelling **users**, **groups**, **systems**, and **roles** in LDAP—implemented as an **authorization graph** using ordinary LDAP entries. Includes a Java API (Apache Directory LDAP API) for creating and querying the model.

## Why

Many organizations already have LDAP/AD as the canonical identity store, but end up re-implementing authorization structures differently per application.

This project proposes:
- **Global groups** (organization-wide)
- **System-scoped roles** (application-specific)
- **Explicit membership/participation edges** represented as dedicated LDAP entries

…so that effective access can be derived with directory searches, without embedding application logic into ad-hoc LDAP schemas.

## Core model

### Entities
- **User** (global)
- **Group** (global)
- **System** (application boundary)
- **Role** (scoped to a System)

### Relationships
- User → Group membership (global)
- User → Role participation (within a system)
- Group → Role participation (within a system)

 Membership and participation are represented as dedicated LDAP entries with:
- `objectClass = groupOfNames`
- `cn = <principalId>`
- `member = <principal DN>`

## Suggested directory layout
```java
dc=example,dc=org
  ├── ou=Users
  │     └── cn=   (inetOrgPerson, …)
  ├── ou=Groups
  │     └── ou=   (organizationalUnit or group container)
  │           └── cn=   (groupOfNames; member=)
  └── ou=Systems
        └── ou=   (organizationalUnit)
              └── ou=Roles
                    └── ou=   (organizationalUnit or role container)
                          ├── cn=   (groupOfNames; member=)
                          └── cn=   (groupOfNames; member=)
```

## Effective access derivation

For a given user:
1. Find global groups where `(objectClass=groupOfNames AND member=<userDN>)`.
2. Find direct roles in any system where `(objectClass=groupOfNames AND member=<userDN>)`.
3. Find indirect roles where `(objectClass=groupOfNames AND member IN <groupDNs>)`.

The union of (2) and (3) yields **effective roles per system**.

## Java API (high-level)

The central entry point is `ApplicationDomain`, which:
- creates systems (`createSystem`)
- assigns users/groups to roles (`assignUserToRole`, `assignGroupToRole`)
- enumerates systems, roles, and groups
- computes effective memberships and roles (direct + via groups)

### Configuration keys (examples)

You can adapt the directory structure via templates and contexts:

- `LDAP_USERS_CONTEXT` (default: `ou=Users,dc=test`)
- `LDAP_GROUPS_CONTEXT` (default: `ou=Groups,dc=test`)
- `LDAP_SYSTEMS_CONTEXT` (default: `ou=Systems,dc=test`)
- `LDAP_ROLE_DN_TEMPLATE` (default: `ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test`)
- `LDAP_USER_IN_ROLE_DN_TEMPLATE` (default: `cn=%s,ou=%s,ou=Roles,ou=%s,ou=Systems,dc=test`)
- `LDAP_GROUP_DN_TEMPLATE` (default: `ou=%s,ou=Groups,dc=test`)

### Minimal usage sketch

```java
Map<String,String> cfg = Map.of(
  "LDAP_USERS_CONTEXT", "ou=Users,dc=gautelis,dc=org",
  "LDAP_GROUPS_CONTEXT", "ou=Groups,dc=gautelis,dc=org",
  "LDAP_SYSTEMS_CONTEXT", "ou=Systems,dc=gautelis,dc=org"
);

ApplicationDomain domain = new ApplicationDomain(cfg);

// Ensure system exists
if (!domain.systemExists("Datastore")) {
  domain.createSystem("Datastore");
}

// Grant role directly
domain.assignUserToRole("alice", "Reader", "Datastore");

// Grant role via group
// (Assumes group exists and alice is in that global Administrators group)
domain.assignGroupToRole("Administrators", "Administrator", "Datastore");
```

## Outcome
The result is a directory-backed RBAC convention with two different scoping levels: **Entities** and **Relationships**

### Entities
- **User** (global): stored under a users context (e.g., `ou=Users,dc=...`), typically `inetOrgPerson` or `sAMAccountName` (configurable).
- **Group** (global): stored under a groups context (e.g., `ou=Groups,dc=...`), with group container entries under `ou=<groupId>,ou=Groups,...`.
- **System** (application / tenant boundary): stored under a systems context (e.g., `ou=Systems,dc=...`), with system entries under `ou=<systemName>,ou=Systems,...`.
- **Role** (system-scoped): stored under a system’s `ou=Roles` subtree:
`ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,...`

### Relationships (“edges”) are represented as entries

That gives you a directory tree that behaves like an authorization graph overlay:

**Global group membership edge**

A user is a member of a global group, if there exists:

```
cn=<userId>,ou=<groupId>,ou=Groups,dc=...
  objectClass: groupOfNames
  cn: <userId>
  member: cn=<userId>,ou=Users,dc=...
```

**Role participation edges (in a specific system)**

A principal (user or group) participates in a role, if there exists:

```
cn=<principalId>,ou=<roleId>,ou=Roles,ou=<systemName>,ou=Systems,dc=...
  objectClass: groupOfNames
  cn: <principalId>
  member: <principalDN>
```

## Effective access

`ApplicationDomain::groupsAndRolesAnalysis` calculates effective access.

Given user-ID and user-DN, `groupsAndRolesAnalysis` computes:
1.	**Global groups**: deep search under groups-context for `(&(objectClass=groupOfNames)(member=<userDn>))`. Extracts group-id from the DN structure.
2.	**Direct roles**: deep search under systems-context using the same `member=<userDn>` filter. Extracts system-name and role-name from DN structure.
3.	**Indirect roles via groups**: builds an OR filter of the user’s group DNs as `member=<groupDn>` and deep searches under systems-context. Extracts system-name and role-name again.

Net result: 

`effective roles per system` = `direct roles` ∪ `roles granted to any global group the user belongs to`.

## Testing

Run tests with the embedded ApacheDS server:

```
mvn test
```

Note: the tests start a local LDAP server on port `10389`.
