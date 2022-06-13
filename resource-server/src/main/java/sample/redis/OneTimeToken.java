package sample.redis;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.time.Instant;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@RedisHash(value = "token", timeToLive = 20)
public class OneTimeToken {

    @Id
    private String accessToken;

    private Instant timestamp;
}
