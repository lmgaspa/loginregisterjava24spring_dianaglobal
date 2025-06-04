package com.dianaglobal.loginregister;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class LoginregisterApplication {

	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

		String mongoPassword = dotenv.get("MONGODB_PASSWORD");
		String jwtSecret = dotenv.get("JWT_SECRET");

		if (mongoPassword != null) {
			System.setProperty("MONGODB_PASSWORD", mongoPassword);
		}
		if (jwtSecret != null) {
			System.setProperty("JWT_SECRET", jwtSecret);
		}

		SpringApplication.run(LoginregisterApplication.class, args);
	}
}

