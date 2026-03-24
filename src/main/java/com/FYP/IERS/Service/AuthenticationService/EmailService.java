package com.FYP.IERS.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.mail.from:${spring.mail.username}}")
    private String fromAddress;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendLoginOtp(String toEmail, String userName, String otpCode, int expiryMinutes) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("Your IERS login verification code");
        message.setText("Hello " + userName + ",\n\n"
                + "Use this one-time verification code to complete your login:\n\n"
                + otpCode + "\n\n"
                + "This code expires in " + expiryMinutes + " minutes and can only be used once.\n"
                + "If you did not attempt to sign in, please change your password immediately.\n\n"
                + "- IERS Security Team");

        mailSender.send(message);
    }

    public void sendPasswordResetOtp(String toEmail, String userName, String otpCode, int expiryMinutes) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(toEmail);
        message.setSubject("Your IERS password reset code");
        message.setText("Hello " + userName + ",\n\n"
                + "Use this one-time verification code to reset your password:\n\n"
                + otpCode + "\n\n"
                + "This code expires in " + expiryMinutes + " minutes and can only be used once.\n"
                + "If you did not request a password reset, please secure your account immediately.\n\n"
                + "- IERS Security Team");

        mailSender.send(message);
    }
}
