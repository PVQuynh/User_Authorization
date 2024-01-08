package com.security.jwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {

    //
    // API có chứa /api/v1/auth thì được phép qua filter
    //
    if (request.getServletPath().contains("/api/v1/auth")) {
      filterChain.doFilter(request, response);
      return;
    }

    //
    //  Không được phép
    //
    // Lấy chuỗi trong authorization
    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String userEmail;

    // Chuoi authorization: bắt đầu bằng bearer, tiếp theo là chuoi tocken
    if (authHeader == null || !authHeader.startsWith("Bearer")) {
      // Nếu authorization không hợp lệ thì chỉ cho đến permitAll
      filterChain.doFilter(request, response);
      return;
    }

    // Xử lý token
    jwt = authHeader.substring(7); // Lấy ra chuỗi token
    userEmail = jwtService.extractUsername(jwt); // claim định danh đảm bảo tính duy nhất
                      // => tư đây có thể truy cập vào db để lấy ra các thông tin khác

    // Kiểm tra xem đúng email ko và có ai đang đăng nhập ko
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      // Lấy ra được UserDetails thông qua userEmail
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

      // Token đã ok
      if (jwtService.isTokenValid(jwt, userDetails)) {
        // Tạo một đối tượng UsernamePasswordAuthenticationToken để đại diện cho thông tin xác thực người dùng
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,                  // Người dùng chi tiết (thường là UserDetails)
                null,                          // Mật khẩu (null vì mật khẩu không được sử dụng trong trường hợp này)
                userDetails.getAuthorities()   // Danh sách các quyền của người dùng
        );

        // Thiết lập chi tiết về xác thực của người dùng, ví dụ: địa chỉ IP, user-agent, etc.
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // Security
        // Đặt thông tin xác thực vào bộ lưu trữ SecurityContextHolder để có thể sử dụng trong quá trình xử lý yêu cầu
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }

    //
    // Hết filter đi đến controller
    //
    filterChain.doFilter(request, response);
  }
}
