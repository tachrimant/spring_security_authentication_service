package com.example.demo.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import static com.example.demo.security.constant.JWTUtil.*;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        if(httpServletRequest.getServletPath().equals("/refrech-token")){
            filterChain.doFilter(httpServletRequest,httpServletResponse);
        }else {
            String authentication_header = httpServletRequest.getHeader(AUTH_HEADER);
            if (authentication_header != null && authentication_header.startsWith(PREFIX)){

                try {
                    String jwtToken = authentication_header.substring(PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwtToken);
                    String username = decodedJWT.getSubject();
                    String[] role = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String r: role) {
                            authorities.add(new SimpleGrantedAuthority(r));
                    }

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null,authorities);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(httpServletRequest,httpServletResponse);
                } catch (Exception e) {
                    httpServletResponse.setHeader("error", e.getMessage());
                    httpServletResponse.sendError(httpServletResponse.SC_FORBIDDEN);
                }
            } else {
                filterChain.doFilter(httpServletRequest,httpServletResponse);
            }
        }
    }
}
