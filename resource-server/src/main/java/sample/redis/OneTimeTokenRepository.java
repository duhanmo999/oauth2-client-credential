package sample.redis;

import org.springframework.data.repository.CrudRepository;

public interface OneTimeTokenRepository extends CrudRepository<OneTimeToken, String> {
}
