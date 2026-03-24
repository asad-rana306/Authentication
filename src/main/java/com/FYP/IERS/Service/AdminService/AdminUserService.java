package com.FYP.IERS.Service.AdminService;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.Entity.User;
import com.FYP.IERS.Exception.AdminOperationException;
import com.FYP.IERS.Exception.UserNotFoundException;
import com.FYP.IERS.Repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminUserService {

    private static final Logger logger = LoggerFactory.getLogger(AdminUserService.class);

    private final UserRepository userRepository;

    public AdminUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public AuthenticationResponse deleteUserByAdmin(Long targetUserId, String actorUserName) {
        logger.info("[ADMIN][DELETE_USER][START] actor={}, targetUserId={}", actorUserName, targetUserId);

        if (targetUserId == null || targetUserId <= 0) {
            logger.warn("[ADMIN][DELETE_USER][INVALID_ID] actor={}, targetUserId={}", actorUserName, targetUserId);
            throw new AdminOperationException("A valid user id is required for deletion.");
        }

        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> {
                    logger.warn("[ADMIN][DELETE_USER][NOT_FOUND] actor={}, targetUserId={}", actorUserName, targetUserId);
                    return new UserNotFoundException("User not found with id: " + targetUserId);
                });

        if (actorUserName != null && actorUserName.equalsIgnoreCase(targetUser.getUserName())) {
            logger.warn("[ADMIN][DELETE_USER][SELF_DELETE_BLOCKED] actor={}, targetUserId={}", actorUserName, targetUserId);
            throw new AdminOperationException("Admin cannot delete own account.");
        }

        userRepository.delete(targetUser);
        logger.info("[ADMIN][DELETE_USER][DELETED] actor={}, targetUserId={}, targetUserName={}",
                actorUserName, targetUserId, targetUser.getUserName());

        return AuthenticationResponse.builder()
                .success(true)
                .message("User deleted successfully by admin.")
                .userId(targetUserId)
                .userName(targetUser.getUserName())
                .timestamp(System.currentTimeMillis())
                .build();
    }
}

