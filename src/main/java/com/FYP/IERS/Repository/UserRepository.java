package com.FYP.IERS.Repository;

import com.FYP.IERS.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long> {
    User findByUserName(String userName);
    Optional<User> findByEmail(String email);
    Optional<User> findByProviderSubject(String providerSubject);
    boolean existsByUserName(String userName);
}
