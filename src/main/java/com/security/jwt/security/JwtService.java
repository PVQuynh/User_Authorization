package com.security.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  @Value("${application.security.jwt.secret-key}")
  private String secretKey;

  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;

  @Value("${application.security.jwt.refresh-token.expiration}")
  private long refreshExpiration;

  // Trích xuất tên người dùng từ token JWT
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  // Trích xuất một claim từ token JWT bằng cách sử dụng hàm claimsResolver được cung cấp
  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  // Tạo một token JWT cho chi tiết người dùng và các claim bổ sung được cung cấp
  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  // Tạo một token JWT với các claim bổ sung cho chi tiết người dùng được cung cấp
  public String generateToken(
          Map<String, Object> extraClaims,
          UserDetails userDetails
  ) {
    return buildToken(extraClaims, userDetails, jwtExpiration);
  }

  // Tạo một refresh token cho chi tiết người dùng được cung cấp
  public String generateRefreshToken(UserDetails userDetails) {
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  // Xây dựng một token JWT với các claim, chi tiết người dùng và thời gian hết hạn được chỉ định
  private String buildToken(
          Map<String, Object> extraClaims,
          UserDetails userDetails,
          long expiration
  ) {
    return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSignInKey(), io.jsonwebtoken.SignatureAlgorithm.HS256)
            .compact();
  }

  // Kiểm tra xem một token JWT cụ thể có hợp lệ cho chi tiết người dùng được cung cấp không
  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  // Kiểm tra xem một token JWT cụ thể đã hết hạn chưa
  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  // Trích xuất ngày hết hạn từ token JWT
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  // Trích xuất tất cả các claim từ token JWT
  private Claims extractAllClaims(String token) {
    return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
  }

  // Lấy khóa ký được sử dụng để ký JWT
  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}