package jp.co.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class CustomUsernamePasswordAuthenticationToken extends
        UsernamePasswordAuthenticationToken {
    private static final long serialVersionUID = 1L;

    public CustomUsernamePasswordAuthenticationToken(Object principal,
            Object credentials) {
        super(principal, credentials);
    }

}
