package com.seungwook.jwt.domain;

import com.seungwook.jwt.enumeration.UserRole;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Entity
@Builder(toBuilder = true) // 객체 수정 허용
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false, unique = true, length = 100)
    private String uuid;// BCrypt 해시 (보안용)

    @Column(nullable = false, unique = true)
    private String searchableHash;  // SHA-256 해시 (검색용)

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, name = "role")
    private UserRole role;
}
