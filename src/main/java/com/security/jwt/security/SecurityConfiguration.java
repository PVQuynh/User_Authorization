package com.security.jwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.security.jwt.enum_constant.Permission.ADMIN_CREATE;
import static com.security.jwt.enum_constant.Permission.ADMIN_DELETE;
import static com.security.jwt.enum_constant.Permission.ADMIN_READ;
import static com.security.jwt.enum_constant.Permission.ADMIN_UPDATE;
import static com.security.jwt.enum_constant.Permission.MANAGER_CREATE;
import static com.security.jwt.enum_constant.Permission.MANAGER_DELETE;
import static com.security.jwt.enum_constant.Permission.MANAGER_READ;
import static com.security.jwt.enum_constant.Permission.MANAGER_UPDATE;
import static com.security.jwt.enum_constant.Role.ADMIN;
import static com.security.jwt.enum_constant.Role.MANAGER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    // Danh sách các URL được phép truy cập mà không cần xác thực
    private static final String[] WHITE_LIST_URL =
            {"/api/v1/auth/**",
            "/v2/api-docs",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui/**",
            "/webjars/**",
            "/swagger-ui.html"};
    private final JwtAuthenticationFilter jwtAuthFilter;  // Filter xác thực JWT
    private final AuthenticationProvider authenticationProvider;  // Đối tượng xử lý xác thực

    /**
     * Bean để cấu hình chuỗi bộ lọc bảo mật.
     *
     * @param http Đối tượng HttpSecurity để cấu hình
     * @return SecurityFilterChain được cấu hình
     * @throws Exception Nếu có lỗi xảy ra trong quá trình cấu hình
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers(WHITE_LIST_URL)
                                .permitAll()
                                .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
                                .anyRequest()
                                .authenticated()

                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf((csrf) -> csrf.disable())
//                .authorizeHttpRequests((authorizeHttpRequests) ->
//                        authorizeHttpRequests
//                                .requestMatchers("/api/**")
//                                .permitAll()
//                                .anyRequest()
//                                .permitAll()
//                )
//                .httpBasic(Customizer.withDefaults())
//                .sessionManagement(Customizer.withDefaults());
//
//
//
//        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
//        http.cors(Customizer.withDefaults());
//
//        return http.build();
//    }
}
