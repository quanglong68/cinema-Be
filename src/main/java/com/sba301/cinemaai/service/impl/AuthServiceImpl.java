package com.sba301.cinemaai.service.impl;


import com.sba301.cinemaai.service.AuthService;
import com.sba301.cinemaai.dto.response.auth.AuthResponse;
import com.sba301.cinemaai.dto.request.auth.GoogleLoginRequest;
import com.sba301.cinemaai.dto.request.auth.GoogleOtpVerifyRequest;
import com.sba301.cinemaai.dto.request.auth.LoginRequest;
import com.sba301.cinemaai.dto.request.auth.RegisterRequest;
import com.sba301.cinemaai.dto.response.auth.RegisterResponse;
import com.sba301.cinemaai.dto.response.user.UserProfileResponse;
import com.sba301.cinemaai.entity.PendingRegistration;
import com.sba301.cinemaai.entity.RefreshToken;
import com.sba301.cinemaai.entity.User;
import com.sba301.cinemaai.enums.RoleName;
import com.sba301.cinemaai.enums.UserStatus;
import com.sba301.cinemaai.exception.BadRequestException;
import com.sba301.cinemaai.exception.ConflictException;
import com.sba301.cinemaai.exception.UnauthorizedException;
import com.sba301.cinemaai.repository.PendingRegistrationRepository;
import com.sba301.cinemaai.repository.UserProfileRepository;
import com.sba301.cinemaai.repository.UserRepository;
import com.sba301.cinemaai.security.JwtProperties;
import com.sba301.cinemaai.security.JwtService;
import com.sba301.cinemaai.service.EmailVerificationService;
import com.sba301.cinemaai.service.GoogleTokenVerifier;
import com.sba301.cinemaai.service.MailService;
import com.sba301.cinemaai.service.RefreshTokenService;
import com.sba301.cinemaai.service.UserRoleService;
import com.sba301.cinemaai.service.UserService;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final int EMAIL_VERIFICATION_EXPIRES_IN_SECONDS = 90;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final UserProfileRepository userProfileRepository;
    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationService emailVerificationService;
    private final UserRoleService userRoleService;
    private final UserService userService;
    private final GoogleTokenVerifier googleTokenVerifier;
    private final MailService mailService;

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        // 1. Giữ nguyên logic kiểm tra trùng lặp Email và SĐT
        if (userRepository.existsByEmail(request.email())) {
            throw new ConflictException("Email already exists");
        }
        if (request.phone() != null && !request.phone().isBlank()) {
            if (userProfileRepository.existsByPhone(request.phone())) {
                throw new ConflictException("Phone already exists");
            }
            // Đã xóa phần kiểm tra trong PendingRegistration vì không dùng tới nữa
        }

        // 2. TẠO THẲNG TÀI KHOẢN CHÍNH THỨC (Bỏ qua PendingRegistration)
        User user = userRepository.save(new User(
                request.email(),
                passwordEncoder.encode(request.password()),
                request.fullName(),
                request.phone(),
                request.birthYear()
        ));
        
        // 3. Kích hoạt tài khoản và gán quyền CUSTOMER ngay lập tức
        activateEmail(user);
        userRoleService.assignRole(user, RoleName.CUSTOMER);

        // 4. (Đã vô hiệu hóa) Không gửi mail OTP nữa
        // mailService.sendOtp(request.email(), "123456", "Email verification");

        // 5. Trả về kết quả báo cho Frontend biết là KHÔNG CẦN OTP (requireOtp = false)
        return new RegisterResponse(
                userService.toProfile(user),
                false, // requireOtp = false -> Frontend sẽ tự động nhảy thẳng vào app
                0
        );
    }

    @Transactional
    public void resendVerificationOtp(String email) {
        PendingRegistration pendingRegistration = pendingRegistrationRepository.findByEmail(email).orElse(null);
        if (pendingRegistration == null) {
            emailVerificationService.resendVerificationOtp(email);
            return;
        }

        refreshPendingRegistration(
                pendingRegistration,
                pendingRegistration.getPasswordHash(),
                pendingRegistration.getFullName(),
                pendingRegistration.getPhone(),
                pendingRegistration.getBirthYear(),
                generateOtp(),
                java.time.LocalDateTime.now(java.time.ZoneId.of("Asia/Ho_Chi_Minh")).plusSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS)
        );
        mailService.sendOtp(pendingRegistration.getEmail(), pendingRegistration.getOtp(), "Email verification");
    }

    @Transactional
    public void verifyEmail(String email, String otp) {
        PendingRegistration pendingRegistration = findPendingRegistration(email, otp);
        if (pendingRegistration == null) {
            emailVerificationService.verifyEmail(email, otp);
            return;
        }
        if (pendingRegistration.getExpiresAt().isBefore(java.time.LocalDateTime.now(java.time.ZoneId.of("Asia/Ho_Chi_Minh")))) {
            throw new BadRequestException("OTP is expired or already used");
        }
        if (userRepository.existsByEmail(pendingRegistration.getEmail())) {
            pendingRegistrationRepository.delete(pendingRegistration);
            throw new ConflictException("Email already exists");
        }
        if (pendingRegistration.getPhone() != null && !pendingRegistration.getPhone().isBlank()
                && userProfileRepository.existsByPhone(pendingRegistration.getPhone())) {
            pendingRegistrationRepository.delete(pendingRegistration);
            throw new ConflictException("Phone already exists");
        }

        User user = userRepository.save(new User(
                pendingRegistration.getEmail(),
                pendingRegistration.getPasswordHash(),
                pendingRegistration.getFullName(),
                pendingRegistration.getPhone(),
                pendingRegistration.getBirthYear()
        ));
        activateEmail(user);
        userRoleService.assignRole(user, RoleName.CUSTOMER);
        pendingRegistrationRepository.delete(pendingRegistration);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
        } catch (DisabledException exception) {
            throw new UnauthorizedException("User is disabled or email is not verified");
        } catch (BadCredentialsException exception) {
            throw new UnauthorizedException("Invalid username or password");
        }

        User user = userService.getByEmail(request.username());
        return createAuthResponse(user);
    }

    @Transactional
    public AuthResponse loginWithGoogle(GoogleLoginRequest request) {
        GoogleTokenVerifier.GoogleTokenInfo tokenInfo = googleTokenVerifier.verify(request.credential());
        User user = userRepository.findByEmail(tokenInfo.email())
                .orElseGet(() -> createGoogleUser(tokenInfo));

        if (user.getStatus() == UserStatus.DISABLED) {
            throw new UnauthorizedException("User is disabled");
        }
        if (!user.isEmailVerified()) {
            activateEmail(user);
        }

        return createAuthResponse(user);
    }

    @Transactional
    public AuthResponse loginWithGoogleOtp(GoogleOtpVerifyRequest request) {
        User user = emailVerificationService.verifyGoogleLogin(request.email(), request.otp());
        if (user.getStatus() == UserStatus.DISABLED) {
            throw new UnauthorizedException("User is disabled");
        }
        return createAuthResponse(user);
    }

    @Transactional
    public AuthResponse refresh(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenService.validate(refreshTokenValue);
        return createAuthResponse(refreshToken.getUser());
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        refreshTokenService.revoke(refreshTokenValue);
    }

    private User createGoogleUser(GoogleTokenVerifier.GoogleTokenInfo tokenInfo) {
        String fullName = tokenInfo.name();
        if (fullName == null || fullName.isBlank()) {
            fullName = tokenInfo.email();
        }

        User user = userRepository.save(new User(
                tokenInfo.email(),
                passwordEncoder.encode(tokenInfo.subject()),
                fullName,
                null
        ));
        activateEmail(user);
        userRoleService.assignRole(user, RoleName.CUSTOMER);
        return user;
    }

    private void refreshPendingRegistration(
            PendingRegistration pendingRegistration,
            String passwordHash,
            String fullName,
            String phone,
            Integer birthYear,
            String otp,
            LocalDateTime expiresAt
    ) {
        pendingRegistration.setPasswordHash(passwordHash);
        pendingRegistration.setFullName(fullName);
        pendingRegistration.setPhone(phone);
        pendingRegistration.setBirthYear(birthYear);
        pendingRegistration.setOtp(otp);
        pendingRegistration.setExpiresAt(expiresAt);
    }

    private void activateEmail(User user) {
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
    }

    private AuthResponse createAuthResponse(User user) {
        List<String> roles = userRoleService.getRoleNames(user.getId());
        RefreshToken refreshToken = refreshTokenService.create(user);
        return new AuthResponse(
                jwtService.generateAccessToken(user.getEmail(), roles),
                refreshToken.getToken(),
                "Bearer",
                jwtProperties.accessExpirationMs(),
                userService.toProfile(user),
                roles
        );
    }

    private PendingRegistration findPendingRegistration(String email, String otp) {
        if (email == null || email.isBlank()) {
            return pendingRegistrationRepository.findFirstByOtpOrderByCreatedAtDesc(otp).orElse(null);
        }
        return pendingRegistrationRepository.findByEmail(email)
                .filter(pendingRegistration -> pendingRegistration.getOtp().equals(otp))
                .orElse(null);
    }

    private UserProfileResponse toPendingProfile(PendingRegistration pendingRegistration) {
        return new UserProfileResponse(
                null,
                pendingRegistration.getEmail(),
                pendingRegistration.getFullName(),
                pendingRegistration.getPhone(),
                null,
                pendingRegistration.getBirthYear(),
                UserStatus.PENDING_VERIFICATION,
                false,
                false,
                List.of(RoleName.CUSTOMER.name()),
                pendingRegistration.getCreatedAt(),
                pendingRegistration.getUpdatedAt()
        );
    }

    private String generateOtp() {
        return String.format("%06d", SECURE_RANDOM.nextInt(1_000_000));
    }
}
