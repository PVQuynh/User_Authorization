package com.security.jwt.service;

import com.security.jwt.dto.request.ChangePasswordRequest;
import com.security.jwt.entity.User;
import com.security.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;

    /**
     * Thay đổi mật khẩu cho người dùng hiện đang xác thực.
     * @param request Thông tin đổi mật khẩu từ người dùng.
     * @param connectedUser Đối tượng Principal của người dùng hiện đang xác thực.
     * @throws IllegalStateException Nếu mật khẩu hiện tại không đúng hoặc mật khẩu mới không trùng khớp.
     */
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {
        // 1. Lấy thông tin người dùng từ đối tượng Principal
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // 2. Kiểm tra xem mật khẩu hiện tại có đúng không
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Mật khẩu hiện tại không đúng");
        }

        // 3. Kiểm tra xem mật khẩu mới và xác nhận mật khẩu mới có trùng khớp không
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Mật khẩu mới và xác nhận mật khẩu mới không trùng khớp");
        }

        // 4. Mã hóa mật khẩu mới và cập nhật vào đối tượng người dùng
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // 5. Lưu thông tin người dùng đã được cập nhật vào cơ sở dữ liệu
        repository.save(user);
    }

}
