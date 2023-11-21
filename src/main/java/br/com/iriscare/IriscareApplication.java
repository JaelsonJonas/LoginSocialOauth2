package br.com.iriscare;

import br.com.iriscare.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class IriscareApplication {

	public static void main(String[] args) {
		SpringApplication.run(IriscareApplication.class, args);
	}

}
