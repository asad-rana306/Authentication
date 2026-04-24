package com.FYP.IERS.Service.AuthenticationService;

import com.FYP.IERS.Entity.User;
import com.FYP.IERS.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserDetailServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(username);
        if (user != null) {
            String password = (user.getPassword() == null || user.getPassword().isBlank())
                    ? "{noop}oauth2-user"
                    : user.getPassword();

            List<String> roles = user.getRoles() == null ? new ArrayList<>(List.of("USER")) : user.getRoles();
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getUserName())
                    .password(password)
                    .roles(roles.toArray(new String[0]))
                    .build();
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }


}