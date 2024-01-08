package com.security.jwt.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.dto.request.AuthenticationRequest;
import com.security.jwt.dto.request.RegisterRequest;
import com.security.jwt.dto.response.AuthenticationResponse;
import com.security.jwt.entity.User;
import com.security.jwt.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;

/**
 * Đối tượng dịch vụ chịu trách nhiệm xử lý các yêu cầu đăng ký, đăng nhập và làm mới token.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final UserRepository userRepository; // Repository để quản lý thông tin người dùng
  private final PasswordEncoder passwordEncoder; // Encoder để mã hóa mật khẩu
  private final JwtService jwtService; // Dịch vụ xử lý token JWT
  private final AuthenticationManager authenticationManager; // Quản lý xác thực
  private final UserDetailService userDetailService;

  /**
   * Đăng ký một người dùng mới và tạo token.
   */
  public ResponseEntity<?> register(RegisterRequest registerRequest) {
    // Tạo đối tượng User từ thông tin đăng ký
    var user = User.builder()
            .firstname(registerRequest.getFirstname())
            .lastname(registerRequest.getLastname())
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(registerRequest.getRole())
            .build();

    // Lưu thông tin người dùng vào cơ sở dữ liệu
    var savedUser = userRepository.save(user);

    return ResponseEntity.ok("User register successfully!");
  }

  /**
   * Xác thực người dùng và tạo token (chưa có token).
   * @return Đối tượng AuthenticationResponse chứa token mới.
   */
  public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
    try {
      // Xác thực người dùng với thông tin đăng nhập so sánh với db
      Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                      authenticationRequest.getEmail(),
                      authenticationRequest.getPassword())
      );

      // Cập nhật security
//      SecurityContextHolder.getContext().setAuthentication(authentication);

      // Lấy ra userDetail
      UserDetail userDetail = (UserDetail) authentication.getPrincipal();

      // Tạo lại token và refresh token cho người dùng đã xác thực
      var jwtToken = jwtService.generateToken(userDetail);
      var refreshToken = jwtService.generateRefreshToken(userDetail);

      // Trả về đối tượng AuthenticationResponse chứa token mới
      return AuthenticationResponse.builder()
              .accessToken(jwtToken)
              .refreshToken(refreshToken)
              .build();

    } catch (AuthenticationException ex) {
      // Xử lý trường hợp xác thực không thành công
      // Ví dụ: log lỗi, trả về thông báo lỗi, ...
      throw new RuntimeException("Tài khoản mật khẩu sai: " + ex.getMessage());
    }
  }

  /**
   * Làm mới token bằng cách sử dụng refresh token.
   * @param request HttpServletRequest chứa thông tin yêu cầu làm mới token.
   * @param response HttpServletResponse để gửi lại token mới.
   * @throws IOException Nếu có lỗi xảy ra trong quá trình xử lý và gửi response.
   */
  public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
    // Lấy giá trị từ Header của request
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;

    //
    // Kiểm tra xem Header Authorization có tồn tại và có bắt đầu bằng "Bearer " không
    //
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      // Nếu không, thoát khỏi phương thức vì không có token cần xử lý
      return;
    }

    //
    // Nếu có token
    //
    // Trích xuất refreshToken từ giá trị của Header
    refreshToken = authHeader.substring(7);

    // Trích xuất userEmail từ refreshToken sử dụng jwtService
    userEmail = jwtService.extractUsername(refreshToken);

    // Kiểm tra xem userEmail có giá trị và tồn tại trong cơ sở dữ liệu không
    if (userEmail != null) {
      UserDetail userDetail = (UserDetail) userDetailService.loadUserByUsername(userEmail);

      // Kiểm tra xem refreshToken có hợp lệ không
      if (jwtService.isTokenValid(refreshToken, userDetail)) {
        // Nếu refreshToken hợp lệ, tạo lại accessToken mới
        var accessToken = jwtService.generateToken(userDetail);

        // Tạo đối tượng AuthenticationResponse với accessToken mới và refreshToken cũ
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        // Ghi đối tượng AuthenticationResponse vào OutputStream của response
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }

    }
  }



}
