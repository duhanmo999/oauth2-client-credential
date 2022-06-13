package sample.interceptor;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import sample.redis.OneTimeToken;
import sample.redis.OneTimeTokenRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class OneTimeTokenValidateInterceptor implements HandlerInterceptor {

    public static final String AUTHORIZATION = "Authorization";
    public static final String DELIMITER = " ";

    private final OneTimeTokenRepository oneTimeTokenRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authorization = request.getHeader(AUTHORIZATION)
                .split(DELIMITER)[1];
        Instant timestamp = Instant.now();
        OneTimeToken oneTimeToken = new OneTimeToken(authorization, timestamp);

        if (oneTimeTokenRepository.existsById(oneTimeToken.getAccessToken())) {
            throw new IllegalStateException("이미 사용한 토큰입니다.");
        }

        oneTimeTokenRepository.save(oneTimeToken);
        return HandlerInterceptor.super.preHandle(request, response, handler);
    }
}
