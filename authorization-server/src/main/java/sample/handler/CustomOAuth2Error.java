package sample.handler;

import lombok.Getter;

import java.io.Serializable;

@Getter
public class CustomOAuth2Error implements Serializable {

    private static final long serialVersionUID = 22L;
    private String code;
    private String message;

    public CustomOAuth2Error() {
    }

    public void toInvalidClient() {
        this.code = "222";
        this.message = "유효하지 않은 클라이언트입니다.";
    }

    public void toUnSupportedGrantType() {
        this.code = "333";
        this.message = "유효하지 않은 grant_type 입니다.";
    }

    public void toDefaultError() {
        this.code = "444";
        this.message = "올바르지 않은 인증 요청 입니다.";
    }
}
