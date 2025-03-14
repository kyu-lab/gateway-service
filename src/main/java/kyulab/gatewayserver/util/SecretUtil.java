package kyulab.gatewayserver.util;

import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class SecretUtil {

	@Value("${jwt.secret}")
	private String secretKeyOrigin;
	private SecretKey secretKey;

	@PostConstruct
	public void createKey() {
		byte[] decodedKey = Base64.getDecoder().decode(secretKeyOrigin);
		this.secretKey = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS512.getJcaName());
	}

	@Bean
	public SecretKey getSecretKey() {
		return this.secretKey;
	}

}
