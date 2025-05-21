package com.seungwook.jwt.jwt;

import com.seungwook.jwt.service.auth.RedisSessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtProvider;
    private final RedisSessionService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException
    {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer "))
        {
            String token = header.substring(7);

            // 블랙리스트 확인
            if (redisService.isBlacklisted(token))
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write("{\"error\": \"Revoked token\"}");
                return;
            }

            if (jwtProvider.validate(token))
            {
                // JWT 토큰에서 직접 정보 추출 (Redis에서 조회하지 않음)
                String uuid = jwtProvider.getUuid(token);
                String role = jwtProvider.getRole(token);

                if (uuid != null && role != null)
                {
                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
                    Authentication auth = new UsernamePasswordAuthenticationToken(uuid, null, Collections.singletonList(authority));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            }
        }

        chain.doFilter(request, response);
    }
}