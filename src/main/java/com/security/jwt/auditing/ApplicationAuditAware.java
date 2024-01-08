package com.security.jwt.auditing;

import com.security.jwt.entity.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<Integer> {

    /**
     * Trả về ID của người dùng hiện đang xác thực (đang thực hiện hành động trong hệ thống).
     * Phương thức này thường được sử dụng trong Spring Data JPA Auditing để lưu thông tin về người tạo
     * hoặc người cập nhật trong các thực thể được đánh dấu với @CreatedBy hoặc @LastModifiedBy.
     *
     * @return ID của người dùng hiện đang xác thực hoặc Optional.empty() nếu không có người dùng nào được xác thực.
     */
    @Override
    public Optional<Integer> getCurrentAuditor() {
        // Lấy thông tin xác thực từ SecurityContextHolder
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Kiểm tra xem người dùng có xác thực không
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty(); // Nếu không có người dùng nào được xác thực, trả về Optional.empty()
        }

        // Lấy thông tin người dùng từ Principal
        User userPrincipal = (User) authentication.getPrincipal();

        // Trả về ID của người dùng (hoặc Optional.empty() nếu không có ID)
        return Optional.ofNullable(userPrincipal.getId());
    }

}
