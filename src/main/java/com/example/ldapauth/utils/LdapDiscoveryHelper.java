package com.example.ldapauth.utils;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

/**
 * Discovers LDAP servers for a domain using DNS SRV lookup of _ldap._tcp.<domain>
 * Results cached for 1 hour via Caffeine.
 */
@Component
public class LdapDiscoveryHelper {
    private static final Logger log = LoggerFactory.getLogger(LdapDiscoveryHelper.class);

    private final Cache<String, List<String>> cache;

    public LdapDiscoveryHelper() {
        cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofHours(1))
                .maximumSize(1000)
                .build();
    }

    public List<String> getLdapServers(String domain) {
        if (domain == null || domain.isBlank()) return List.of();
        List<String> fromCache = cache.getIfPresent(domain.toLowerCase());
        if (fromCache != null) {
            log.debug("Using cached LDAP servers for {}", domain);
            return fromCache;
        }

        List<String> discovered = discoverViaSrv(domain);
        if (discovered.isEmpty()) {
            log.debug("No SRV records found for {}, falling back to A lookup", domain);
            // fallback: use domain itself
            discovered.add(domain);
        }

        cache.put(domain.toLowerCase(), discovered);
        return discovered;
    }

    private List<String> discoverViaSrv(String domain) {
        List<String> servers = new ArrayList<>();
        String query = "_ldap._tcp." + domain;
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        try {
            DirContext ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(query, new String[]{"SRV"});
            Attribute srv = attrs.get("SRV");
            if (srv != null) {
                NamingEnumeration<?> en = srv.getAll();
                while (en.hasMore()) {
                    String rec = (String) en.next();
                    // SRV record format: priority weight port target
                    String[] parts = rec.trim().split("\\s+");
                    if (parts.length >= 4) {
                        String port = parts[2];
                        String host = parts[3];
                        // strip trailing dot from host if present
                        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
                        servers.add(host + ":" + port);
                    }
                }
            }
            ctx.close();
        } catch (NamingException e) {
            log.warn("DNS SRV lookup failed for {}: {}", query, e.getMessage());
        }
        return servers;
    }
}
