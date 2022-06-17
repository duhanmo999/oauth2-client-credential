# oauth2-client-credential with Redis
access-token 의 만료시간이 남았어도 **한 번의 Request 당 한 번의 access-token 만 사용이 가능**한 서버를 제작했습니다.
## oauth2 client-credential 방식이란 
**oauth2 의 4가지 방식중 client-credential flow**   
보호된 리소스인 clientId 와 clientSecret 을 이용하여 인증서버에서 access-token 을 발급받습니다.      
이 후 해당 토큰을 Resource server 요청헤더에 추가하여 자원을 요청(또는 처리)합니다.

<img width="559" alt="image" src="https://user-images.githubusercontent.com/44223292/173312961-ffc46803-d6fb-44fa-a7d6-b5782648ef7a.png">

>  https://datatracker.ietf.org/doc/html/rfc6749

해당 그림에서는 access-token 을 발급 받는 부분까지만 나타나 있지만, 실제 발급받은 토큰을 이용해 자원서버에 요청 해야합니다.

## 하나의 access-token 으로 한 번의 요청만 허용하려면?
**idea**
1. 스프링이 관리하는 authorization(access-token) JDBC를 이용한다. (이슈 존재)
   1. client, authorization 관련 schema 를 생성
   2. 해당 정보들을 관리하는 구현체를 InMemory 가 아닌 JDBC 를 이용
   3. 설정된 정보, 발급한 토큰을 잘 저장하긴 하지만 요청마다 DB 의 삽입, 삭제를 하기엔 **효율이 떨어짐**
2. Redis 를 이용한다.
   1. 발급한 access-token 값을 Redis 에 저장
   2. Redis 에 저장할 때 lifetime 을 access-token의 만료시간과 일치시킴
   3. 하지만 Spring Authorization-server 자체에서 이용하고 있는 로직 사이에 Redis 에 관한 로직을 삽입하기가 힘듬
   4. 대책으로 Resource-server 에서 Redis 관련한 로직을 구현
   
다시 말해, Authorization-server 에서는 access-token (jwt) 자체 signature 를 해석해 유효성을 판단하고,  
Resource-server 에서는 Redis 를 이용해 access-token 자체를 단 한번만 사용이 가능하도록 만듭니다.  

## 구현 방식
### Authorization-server
실제 인증서버는 spring-boot-starter-oauth2-resource-server 라이브러리를 이용합니다.
> implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'  
>
(여담이지만 스프링 시큐리티에서 제공하던 OAuth2 라이브러리는 지원을 중단했고 Spring 에서 새롭게 제작하는 라이브러리라고 합니다. 그래서 버전이낮음..)  
spring 에서는 client 와 authorization 관련한 정보들을 2가지 방식으로 저장, 관리 합니다. 
1. InMemory
2. JDBC

InMemory 방식은 개발, 테스트 시에만 사용해야 합니다.

1. clientId 와 clientSecret 은 secret yml 파일로 관리하여 실제로는 git 에 올라가지 않도록 주의합니다.
```java
@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private String issuer;
    private Map<String, String> client; // key: clientId , value: clientSecret
}
```
2. 위와 같이 yml 파일 값을 읽어옵니다. 이후 아래 설정파일에 주입합니다.
```java
// OAuth2AuthorizationServerSecurityConfiguration.class
private final AuthProperties authProperties;

public OAuth2AuthorizationServerSecurityConfiguration(AuthProperties authProperties) {
        this.authProperties = authProperties;
        }
        ...
 @Bean
 public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
     RegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

     Map<String, String> client = authProperties.getClient();
     for (Map.Entry<String, String> clientEntrySet : client.entrySet()) {
         String clientId = clientEntrySet.getKey();
         String clientSecret = clientEntrySet.getValue();
         boolean existClient = registeredClientRepository.findByClientId(clientId) != null;
         if (!existClient) {
             saveNewClient(registeredClientRepository, clientId, clientSecret);
         }
     }
     return registeredClientRepository;
 }

 private void saveNewClient(RegisteredClientRepository registeredClientRepository, String clientId, String clientSecret) {
     RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
             .clientId(clientId)
             .clientSecret(clientSecret)
             .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
             .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
             /* 토큰의 lifetime 설정
             .tokenSettings(TokenSettings.builder()
                     .accessTokenTimeToLive(Duration.ofMillis(5000L))
                     .build())
              */
             .scope("message:read")
             .scope("message:write")
             .build();
     registeredClientRepository.save(registeredClient);
 }
```
3. 이 후 서버가 만약 재기동 해도 기존 client 를 새롭게 저장하는걸 방지하기 위해 로직을 구현합니다.
4. 스프링 시큐리티가 저장된 clientSecret 값을 디코딩해서 가져오기 때문에 반드시 암호화를 진행해야 합니다.(테스트를 위해서는 {noop}test 같이 암호화를 하지 않아도 됩니다.)
```yaml
# local-secret.yml
auth:
  issuer: "http://localhost:9000"
  client:
    clientIdExam1: "{bcrypt}$2a$10$qdplIH6LR0hJOb3EmWotBOr3D/1G8qhkF06NMEsNxf7boKarDL176"
    clientIdExam2: "{bcrypt}$2a$10$vY/61rZvKq5GYu6GAUshFeaGWvf5nqnc8Zst5owVYRQsF.PIcyTCC"

```
이렇게 설정을 해놓으면 실제 client 와 access-token (실제로는 더 많은 정보를 저장) 을 DB 를 통해 관리할 수 있습니다.
## Resource-server 
1. 요청헤더에 담긴 access-token 을 검사하기 위해 Authorization-server 에 전송하는 url 은 yml 파일에 지정합니다.
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:9000/oauth2/jwks
```
2. 인터셉터를 구현하여 요청헤더에 담긴 access-token 을 Redis 에 저장 또는 중복체크 합니다.
```java
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
```

위와 같이 핵심 로직을 이해한다면 실제 소스코드를 보더라도 큰 어려움이 없을 것으로 예상됩니다.  

## 실제 테스트를 해보기 위한 EndPoint
```shell
# 토큰 발행
curl --location --request POST 'clientIdExam1:test@localhost:9000/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'scope=message:write message:read'
```
**PostMan 을 이용할 땐** 
1. Authorization 탭 -> Type: Basic Auth -> username, password 에 각각 clientId, clientSecret 지정
2. Body 탭 -> x-www-form-urlencoded -> key, value 값에 각각 grant_type: client_credentials, scope: message:write message:read 지정 

```shell
# GetMethod Test
curl --location --request GET 'localhost:8080' \
--header 'Authorization: Bearer {access-token}'
```

```shell
# PostMethod Test
curl --location --request POST 'localhost:8080/message' \
--header 'Authorization: Bearer {access-token}' \
--header 'Content-Type: text/plain' \
--data-raw 'something-string'
```
**PostMan 을 이용할 땐**
1. Authorization 탭 -> Type: Bearer Token -> 발급받은 access-token 값 지정

## 필요한 세팅
1. mysql
2. redis

### reference
> https://github.com/spring-projects/spring-authorization-server