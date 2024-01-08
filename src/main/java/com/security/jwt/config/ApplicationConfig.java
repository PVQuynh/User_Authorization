package com.security.jwt.config;

import com.security.jwt.auditing.ApplicationAuditAware;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Cấu hình ứng dụng Spring, bao gồm cấu hình cho xác thực người dùng, mã hóa mật khẩu, và quản lý phiên làm việc.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final UserDetailsService userDetailsService;

  /**
   * Bean cung cấp một AuthenticationProvider để Spring Security có thể xác thực người dùng.
   * @return AuthenticationProvider được cấu hình với UserDetailsService và PasswordEncoder.
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    // Tạo một đối tượng DaoAuthenticationProvider, là một implementation của AuthenticationProvider.
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

    // Thiết lập UserDetailsService mà Spring Security sẽ sử dụng để tìm kiếm thông tin người dùng.
    authProvider.setUserDetailsService(userDetailsService);

    // Thiết lập PasswordEncoder mà Spring Security sẽ sử dụng để kiểm tra mật khẩu.
    authProvider.setPasswordEncoder(passwordEncoder());

    // Trả về AuthenticationProvider đã được cấu hình.
    return authProvider;
  }

  /**
   * Bean cung cấp một AuthenticationManager để Spring Security có thể quản lý xác thực người dùng.
   * @param config AuthenticationConfiguration được inject vào để lấy AuthenticationManager.
   * @return AuthenticationManager được cấu hình.
   * @throws Exception Nếu có lỗi xảy ra trong quá trình cấu hình.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }

  /**
   * Bean cung cấp một PasswordEncoder để mã hóa mật khẩu người dùng.
   * Đối tượng này được cấu hình với BCryptPasswordEncoder để đảm bảo an toàn và bảo mật mật khẩu.
   * @return PasswordEncoder - Đối tượng mã hóa mật khẩu.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Bean cung cấp một AuditorAware để xác định ai đang thực hiện hành động kiểm định.
   * Trong trường hợp này, sử dụng đối tượng ApplicationAuditAware để cung cấp thông tin về người thực hiện.
   * @return AuditorAware<Integer> - Đối tượng giúp xác định người thực hiện hành động kiểm định.
   */
  @Bean
  public AuditorAware<Integer> auditorAware() {
    return new ApplicationAuditAware();
  }
}

