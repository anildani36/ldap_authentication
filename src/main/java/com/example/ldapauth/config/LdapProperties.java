package com.example.ldapauth.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Put sensitive values in environment variables or Spring config.
 */
@Component
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LdapProperties {
    // Service account used to search for the user DN (required when directory doesn't allow anonymous search)
    @Value("${ldap.service.bind.dn:cn=svc,dc=example,dc=com}")
    private String serviceBindDN;

    @Value("${ldap.service.bind.password:change-this}")
    private String serviceBindPassword;

    // default search base (can be overridden per-domain in advanced setup)
    @Value("${ldap.base.dn:dc=example,dc=com}")
    private String baseDN;

    @Value("${ldap.search.filter:(sAMAccountName={0})}")
    private String userSearchFilter; // use {0} to insert username

    @Value("${ldap.connect.timeout.millis:3000}")
    private int connectTimeoutMillis;

    @Value("${ldap.read.timeout.millis:5000}")
    private int readTimeoutMillis;

}
