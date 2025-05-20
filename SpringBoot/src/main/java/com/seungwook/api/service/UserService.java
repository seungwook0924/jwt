package com.seungwook.api.service;

import com.seungwook.api.domain.User;
import com.seungwook.api.enumeration.UserRole;
import com.seungwook.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // UUID 해시 캐싱을 위한 맵 (성능 최적화)
    private final ConcurrentHashMap<String, String> uuidHashCache = new ConcurrentHashMap<>();

    /**
     * 회원가입 - UUID 생성 및 해시 후 저장
     */
    public String registerNewUser(UserRole role) {
        String rawUuid = UUID.randomUUID().toString();
        String bcryptHashed = passwordEncoder.encode(rawUuid);
        String searchableHash = sha256Hash(rawUuid);  // 검색용 해시 생성

        User user = userRepository.save(User.builder()
                .uuid(bcryptHashed)
                .searchableHash(searchableHash)  // 검색용 해시 저장
                .role(role)
                .build());

        // 캐시에 UUID 해시 저장
        uuidHashCache.put(rawUuid, user.getUuid());

        return rawUuid;
    }

    /**
     * UUID 원문으로 사용자 조회 (로그인) - 성능 개선 버전
     */
    public User findByRawUuid(String rawUuid) {
        // 1. 캐시에서 먼저 확인
        String cachedHash = uuidHashCache.get(rawUuid);
        if (cachedHash != null) {
            return userRepository.findByUuid(cachedHash)
                    .orElseThrow(() -> new UsernameNotFoundException("UUID 인증 실패: 캐시된 사용자 없음"));
        }

        // 2. searchableHash를 사용하여 빠르게 검색
        String searchableHash = sha256Hash(rawUuid);
        User user = userRepository.findBySearchableHash(searchableHash)
                .orElseThrow(() -> new UsernameNotFoundException("UUID 인증 실패"));

        // 3. 최종 보안 검증
        if (passwordEncoder.matches(rawUuid, user.getUuid())) {
            // 캐시에 추가
            uuidHashCache.put(rawUuid, user.getUuid());
            return user;
        }

        throw new UsernameNotFoundException("UUID 인증 실패");
    }

    /**
     * 캐시 무효화 (사용자 정보 변경 시 호출)
     */
    public void invalidateCache(String rawUuid) {
        uuidHashCache.remove(rawUuid);
    }

    /**
     * SHA-256 해시 생성 (검색용)
     */
    private String sha256Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("해시 생성 실패", e);
        }
    }
}