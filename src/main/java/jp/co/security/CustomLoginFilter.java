package jp.co.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter{

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: "
                    + request.getMethod());
        }

        // Obtain UserName, Password, CompanyId
        String username = super.obtainUsername(request);
        String password = super.obtainPassword(request);

        if ("admin".equals(username)) {
            if (!"admin".equals(password)) {
                throw new AuthenticationServiceException("Password is invalid.");
            }
        } else if ("user".equals(username)) {
            if (!"user".equals(password)) {
                throw new AuthenticationServiceException("Password is invalid.");
            }
        } else {
            //throw new AuthenticationServiceException("User Name is invalid.");
            //throw new AuthException("Authentication Error");
            throw new AuthenticationServiceException("User Name is invalid.");
        }
        // username required
        //if (!StringUtils.hasText(username)) {
        //    throw new AuthenticationServiceException("UserName is required");
        //}

        // validate password, companyId

        // omitted other process

        CustomUsernamePasswordAuthenticationToken authRequest =
                new CustomUsernamePasswordAuthenticationToken(username, password);

        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
