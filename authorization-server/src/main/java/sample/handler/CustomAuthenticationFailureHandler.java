package sample.handler;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component("customAuthenticationFailureHandler")
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final MappingJackson2HttpMessageConverter errorHttpResponseConverter;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();

        CustomOAuth2Error errorResponse = new CustomOAuth2Error();
        switch (error.getErrorCode()) {
            case OAuth2ErrorCodes.INVALID_CLIENT:
                httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
                errorResponse.toInvalidClient();
                break;
            case OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE:
                httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
                errorResponse.toUnSupportedGrantType();
                break;
            default:
                httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
                errorResponse.toDefaultError();
                break;
        }

        errorHttpResponseConverter.write(errorResponse, MediaType.APPLICATION_JSON, httpResponse);
    }
}
