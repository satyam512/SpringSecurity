package com.darkKnight.rbacAndspringsecurity.service;

import com.darkKnight.rbacAndspringsecurity.model.MyUserDetails;
import com.darkKnight.rbacAndspringsecurity.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(s);
        if(user == null)
            throw new UsernameNotFoundException("Keep searching ... ");
        return new MyUserDetails(user);
    }
}
