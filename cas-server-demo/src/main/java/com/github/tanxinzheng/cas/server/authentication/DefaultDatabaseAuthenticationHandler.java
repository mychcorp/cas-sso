package com.github.tanxinzheng.cas.server.authentication;

import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Created by Jeng on 2015/10/17.
 */
public class DefaultDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

    @NotNull
    private String sql;



    /**
     * Authenticates a username/password credential by an arbitrary strategy.
     *
     * @param transformedCredential the credential object bearing the transformed username and password.
     * @return HandlerResult resolved from credential on authentication success or null if no principal could be resolved
     * from the credential.
     * @throws java.security.GeneralSecurityException          On authentication failure.
     * @throws org.jasig.cas.authentication.PreventedException On the indeterminate case when authentication is prevented.
     */
    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {
        final String username = credential.getUsername();
        final String password = credential.getPassword();
        String plain = Encodes.unescapeHtml(password);
        byte[] salt = Digests.generateSalt(8);
        byte[] hashPassword = Digests.sha1(plain.getBytes(), salt, 1024);
        String encryptedPassword = Encodes.encodeHex(hashPassword);
//        String salt = (String) saltSource.getSalt(credential);
//        String encryptedPassword = MD5Utils.encrypt(password, salt);
        try {
            String e = (String)this.getJdbcTemplate().queryForObject(this.sql, String.class, new Object[]{username});
            if(!e.equals(encryptedPassword)) {
                throw new FailedLoginException("Password does not match value on record.");
            }
        } catch (IncorrectResultSizeDataAccessException var5) {
            if(var5.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            }

            throw new FailedLoginException("Multiple records found for " + username);
        } catch (DataAccessException var6) {
            throw new PreventedException("SQL exception while executing query for " + username, var6);
        }

        return this.createHandlerResult(credential, new SimplePrincipal(username), (List)null);
    }

    public void setSql(String sql) {
        this.sql = sql;
    }


}
