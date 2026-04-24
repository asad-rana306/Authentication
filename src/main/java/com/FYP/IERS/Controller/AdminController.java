package com.FYP.IERS.Controller;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.Service.AdminService.AdminUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

	private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

	private final AdminUserService adminUserService;

	public AdminController(AdminUserService adminUserService) {
		this.adminUserService = adminUserService;
	}

	@DeleteMapping("/users/{userId}")
	public ResponseEntity<AuthenticationResponse> deleteUserByAdmin(
			@PathVariable Long userId,
			Authentication authentication
	) {
		String actor = authentication == null ? "anonymous" : authentication.getName();
		logger.info("Admin delete user request received. Actor: {}, Target user id: {}", actor, userId);

		AuthenticationResponse response = adminUserService.deleteUserByAdmin(userId, actor);

		logger.info("Admin deleted user successfully. Actor: {}, Target user id: {}", actor, userId);
		return ResponseEntity.ok(response);
	}
}
