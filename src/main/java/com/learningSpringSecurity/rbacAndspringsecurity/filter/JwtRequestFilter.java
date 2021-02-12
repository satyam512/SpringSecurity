package com.learningSpringSecurity.rbacAndspringsecurity.filter;

import com.learningSpringSecurity.rbacAndspringsecurity.service.MyUserDetailsService;
import com.learningSpringSecurity.rbacAndspringsecurity.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final String SECRET_KEY = "SomethingElse";

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = httpServletRequest.getHeader("Authorization");

        String username = null;
        String token = null;

        try {
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                token = authorizationHeader.substring(7);
            }
            Jws<Claims> claimsJws = Jwts.parser().
                    setSigningKey(SECRET_KEY).
                    parseClaimsJws(token);
            Claims body = claimsJws.getBody();
            username = body.getSubject();

            Set<SimpleGrantedAuthority> authorities = ((List<Map<String, String >>) body.get("authorities")).stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    authorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException ex) {
            throw new IllegalStateException(String.format("Token %s cannot be verified", token));
        }
        // signalling subsequent filters
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
