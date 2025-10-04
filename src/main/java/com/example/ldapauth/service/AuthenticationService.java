package com.example.ldapauth.service;

import com.example.ldapauth.config.LdapProperties;
import com.example.ldapauth.model.AuthRequest;
import com.example.ldapauth.model.AuthResponse;
import com.example.ldapauth.utils.LdapDiscoveryHelper;
import com.unboundid.ldap.sdk.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Core auth service. authenticate() implements:
 *  - discover LDAP servers (cached 1 hour)
 *  - search user DN using service account
 *  - attempt bind as user to validate credentials
 *  - exponential retry on transient errors per server, then move to next server
 */
@Service
public class AuthenticationService {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final LdapProperties props;
    private final LdapDiscoveryHelper discoveryHelper;

    // retries/backoff configuration
    private static final int MAX_RETRIES_PER_SERVER = 2;
    private static final long BACKOFF_BASE_MILLIS = 200; // exponential base

    public AuthenticationService(LdapProperties props, LdapDiscoveryHelper discoveryHelper) {
        this.props = props;
        this.discoveryHelper = discoveryHelper;
    }

    public AuthResponse authenticate(AuthRequest request) {
        if (request.getUsername() == null || request.getPassword() == null) {
            return AuthResponse.failure(HttpStatus.BAD_REQUEST, "invalid_request", "username and password required");
        }
        final String username = request.getUsername();
        final String password = request.getPassword();
        final String domain = (request.getDomain() != null) ? request.getDomain() : extractDomainFromUsername(username);

        if (domain == null) {
            return AuthResponse.failure(HttpStatus.BAD_REQUEST, "invalid_domain", "could not determine domain");
        }

        // get list of ldap servers (cached)
        List<String> servers = discoveryHelper.getLdapServers(domain);
        if (servers == null || servers.isEmpty()) {
            return AuthResponse.failure(HttpStatus.SERVICE_UNAVAILABLE, "no_servers", "No LDAP servers discovered for domain: " + domain);
        }

        // Try servers in order, with retries and backoff for transient errors
        for (String server : servers) {
            log.debug("Trying LDAP server: {}", server);
            String host;
            int port = 389;
            if (server.contains(":")) {
                String[] parts = server.split(":");
                host = parts[0];
                port = Integer.parseInt(parts[1]);
            } else {
                host = server;
            }

            int attempt = 0;
            while (attempt <= MAX_RETRIES_PER_SERVER) {
                try {
                    // Connect with a short timeout and optionally use StartTLS/LDAPS depending on your infra
                    LDAPConnectionOptions options = new LDAPConnectionOptions();
                    options.setConnectTimeoutMillis(props.getConnectTimeoutMillis());
                    options.setResponseTimeoutMillis(props.getReadTimeoutMillis());

                    // For simplicity we use simple LDAP (non-SSL). In production prefer LDAPS or StartTLS.
                    try (LDAPConnection conn = new LDAPConnection(options, host, port)) {
                        // 1) Bind with service account to search for user DN
                        BindResult svcBind = conn.bind(props.getServiceBindDN(), props.getServiceBindPassword());
                        if (!svcBind.getResultCode().equals(ResultCode.SUCCESS)) {
                            // service account bind failed; treat as transient/unavailable
                            log.warn("Service bind failed on {}: {}", server, svcBind.getDiagnosticMessage());
                            throw new LDAPException(svcBind.getResultCode(), "service bind failed: " + svcBind.getDiagnosticMessage());
                        }

                        // 2) Search for user DN
                        String filter = props.getUserSearchFilter().replace("{0}", escapeLDAPSearchFilter(username));
                        SearchResult search = conn.search(props.getBaseDN(), SearchScope.SUB, filter, "distinguishedName", "dn");
                        if (search.getEntryCount() == 0) {
                            return AuthResponse.failure(HttpStatus.UNAUTHORIZED, "user_not_found", "User not found");
                        }
                        SearchResultEntry entry = search.getSearchEntries().get(0);
                        String userDN = entry.getDN();

                        // 3) Try bind as user (validate credentials)
                        try (LDAPConnection userConn = new LDAPConnection(options, host, port)) {
                            BindResult userBind = userConn.bind(userDN, password);
                            if (userBind.getResultCode() == ResultCode.SUCCESS) {
                                // success
                                return AuthResponse.ok(server);
                            } else {
                                // map AD/LDAP specific codes to detailed messages
                                String mapped = mapBindError(userBind);
                                return AuthResponse.failure(HttpStatus.UNAUTHORIZED, "invalid_credentials", mapped);
                            }
                        }
                    }

                } catch (LDAPException e) {
                    log.warn("LDAPException on {} attempt {}: {}", server, attempt, e.getMessage());
                    // decide whether to retry (transient) or move on (auth error)
                    if (isBindFailure(e)) {
                        // invalid creds or account issues -> return with mapped message
                        String mapped = mapLDAPException(e);
                        return AuthResponse.failure(HttpStatus.UNAUTHORIZED, "ldap_bind_failed", mapped);
                    }
                    // else treat as transient: backoff and retry, up to attempts, then break to next server
                    attempt++;
                    if (attempt > MAX_RETRIES_PER_SERVER) {
                        log.info("max retries reached for {}, moving to next server", server);
                        break;
                    }
                    try {
                        long backoff = BACKOFF_BASE_MILLIS * (1L << (attempt - 1));
                        TimeUnit.MILLISECONDS.sleep(backoff);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return AuthResponse.failure(HttpStatus.INTERNAL_SERVER_ERROR, "interrupted", "Interrupted during retry backoff");
                    }
                } catch (Exception ex) {
                    log.error("Unexpected error contacting LDAP server {}: {}", server, ex.getMessage());
                    // move to next server
                    break;
                }
            } // attempts loop
        } // server loop

        return AuthResponse.failure(HttpStatus.SERVICE_UNAVAILABLE, "all_unreachable", "All LDAP servers unreachable or failed");
    }

    // Helper: shallow domain extraction
    private String extractDomainFromUsername(String username) {
        // Accepts user@domain or DOMAIN\\user or plain user (fallback)
        if (username.contains("@")) {
            String[] parts = username.split("@");
            return parts[1].toLowerCase();
        }
        if (username.contains("\\")) {
            String[] parts = username.split("\\\\");
            return parts[0].toLowerCase();
        }
        return null;
    }

    private boolean isBindFailure(LDAPException e) {
        ResultCode rc = e.getResultCode();
        if (rc == null) return false;
        // invalid credentials (49) often returned for bad password; treat as auth error
        return rc == ResultCode.INVALID_CREDENTIALS ||
                rc == ResultCode.INSUFFICIENT_ACCESS_RIGHTS ||
                rc == ResultCode.NO_SUCH_OBJECT;
    }

    // Map common bind responses to human-friendly text; for AD check diagnosticMessage for subcodes
    private String mapBindError(BindResult bindResult) {
        ResultCode rc = bindResult.getResultCode();
        String msg = bindResult.getDiagnosticMessage();
        if (rc == ResultCode.INVALID_CREDENTIALS) {
            // AD often returns DSID message with data code; attempt to parse
            String ad = parseActiveDirectoryDiagnostic(msg);
            return "Invalid credentials" + (ad != null ? (": " + ad) : "");
        }
        return rc.toString() + " - " + msg;
    }

    private String mapLDAPException(LDAPException e) {
        ResultCode rc = e.getResultCode();
        String msg = e.getDiagnosticMessage();
        if (rc == ResultCode.INVALID_CREDENTIALS) {
            String ad = parseActiveDirectoryDiagnostic(msg);
            return "Invalid credentials" + (ad != null ? (": " + ad) : "");
        } else if (rc == ResultCode.CONNECT_ERROR || rc == ResultCode.SERVER_DOWN) {
            return "LDAP server unreachable: " + msg;
        } else if (rc == ResultCode.NO_SUCH_OBJECT) {
            return "User not found";
        } else {
            return rc + " - " + msg;
        }
    }

    // parse AD diagnostic messages to extract subcode mapping (e.g., "data 52e" etc.)
    private String parseActiveDirectoryDiagnostic(String diag) {
        if (diag == null) return null;
        String lower = diag.toLowerCase();
        if (lower.contains("data 525")) return "user not found (525)";
        if (lower.contains("data 52e")) return "invalid credentials (52e)";
        if (lower.contains("data 530")) return "not permitted to logon at this time (530)";
        if (lower.contains("data 531")) return "not permitted to logon at this workstation (531)";
        if (lower.contains("data 532")) return "password expired (532)";
        if (lower.contains("data 533")) return "account disabled (533)";
        if (lower.contains("data 701")) return "account expired (701)";
        if (lower.contains("data 775")) return "account locked (775)";
        // fallback: return raw diag message
        return diag;
    }

    // simple escape for LDAP search filters
    private static String escapeLDAPSearchFilter(String filter) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filter.length(); i++) {
            char ch = filter.charAt(i);
            switch (ch) {
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default: sb.append(ch);
            }
        }
        return sb.toString();
    }
}
