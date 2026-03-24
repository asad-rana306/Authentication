package com.FYP.IERS.Service;

import com.FYP.IERS.Entity.User;
import com.FYP.IERS.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServices {

    @Autowired
    private UserRepository userRepository;
    public User addUser(User user) {
        if (userRepository.findByUserName(user.getUserName()) != null) {
            throw new RuntimeException("This ID is already taken, please choose another.");
        }
        return userRepository.save(user);
    }
}