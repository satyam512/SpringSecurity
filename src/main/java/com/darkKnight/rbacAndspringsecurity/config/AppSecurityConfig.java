package com.darkKnight.rbacAndspringsecurity.config;

import com.darkKnight.rbacAndspringsecurity.fliter.JwtRequestFilter;
import com.darkKnight.rbacAndspringsecurity.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                .antMatchers("/authenticate").permitAll() // need to do something to login page if this is being used
                .antMatchers("/admin").hasAuthority("ADMIN")
                .antMatchers("/users").hasAnyAuthority("ADMIN", "USER")
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // now no session will be created i.e server will not remember if user logged in or not
//                .and().formLogin(); // this removes the default login and also now for unauthorized resource accesses it will simple return 403 forbidden instead of redirecting to login
        //  adds the jwt filter before use UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
//http.csrf().disable().authorizeRequests()
//                .antMatchers("/authenticate").permitAll()
//                .anyRequest().authenticated()
//                .antMatchers("/admin").hasAuthority("ADMIN")
//                .antMatchers("/users").hasAnyAuthority("ADMIN", "USER")
//                .antMatchers("/").permitAll()
//                .and().formLogin();