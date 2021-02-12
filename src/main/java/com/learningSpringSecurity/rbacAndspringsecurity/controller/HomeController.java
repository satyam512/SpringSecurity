package com.learningSpringSecurity.rbacAndspringsecurity.controller;
import com.learningSpringSecurity.rbacAndspringsecurity.model.AuthenticationRequest;
import com.learningSpringSecurity.rbacAndspringsecurity.model.AuthenticationResponse;
import com.learningSpringSecurity.rbacAndspringsecurity.service.MyUserDetailsService;
import com.learningSpringSecurity.rbacAndspringsecurity.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class HomeController {
    @Autowired
    private AuthenticationManager authenticationManager; // need to add bean for this

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @GetMapping(value = "/")  // accessible to everyone even those who're not logged in
    public ModelAndView homePage() {
        ModelAndView mav = new ModelAndView("freeForAll");
        return mav;
    }

    @GetMapping(value = "/users")  // accessible to everyone even those who're not logged in
    public ModelAndView usersPage() {
        ModelAndView mav = new ModelAndView("usersAndAdminsOnly");
        return mav;
    }
    @GetMapping(value = "/admin")  // accessible to everyone even those who're not logged in
    public ModelAndView adminsOnly() {
        ModelAndView mav = new ModelAndView("imBatman");
        return mav;
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()));
        }catch (BadCredentialsException ex) {
            ex.printStackTrace();
        }

        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(jwtUtil.generateToken(userDetails));

        return ResponseEntity.ok(authenticationResponse);
    }
}
