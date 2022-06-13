package sample.interceptor;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class OneTimeTokenValidateInterceptorConfig implements WebMvcConfigurer {

    private final OneTimeTokenValidateInterceptor oneTimeTokenValidateInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(oneTimeTokenValidateInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns();
    }
}
