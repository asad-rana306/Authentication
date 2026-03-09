package com.FYP.IERS.Repository;

import com.FYP.IERS.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long> {
    User findByUserName(String userName);
}
