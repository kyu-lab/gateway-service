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

	@Value("${jwt.access-token:}")
	private String accessKeyOrigin;
	private SecretKey accessKey;

	@PostConstruct
	public void createKey() {
		byte[] accessDecodedKey = Base64.getDecoder().decode(accessKeyOrigin);
		this.accessKey = new SecretKeySpec(accessDecodedKey, SignatureAlgorithm.HS512.getJcaName());
	}

	@Bean
	public SecretKey getAccessKey() {
		return this.accessKey;
	}

}
