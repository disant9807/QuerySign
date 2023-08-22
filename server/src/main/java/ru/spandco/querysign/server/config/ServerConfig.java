package ru.spandco.querysign.server.config;
import org.springdoc.core.SwaggerUiConfigProperties;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@ComponentScan(basePackages = "ru.spandco.binstorageproxy")
@ComponentScan(basePackages = "ru.spandco.querysign.server.service")
public class ServerConfig implements WebMvcConfigurer {

  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }

  @Bean
  WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> enableDefaultServlet() {
    return (factory) -> factory.setRegisterDefaultServlet(true);
  }

  @Bean
  public SwaggerUiConfigProperties swaggerUiConfig(SwaggerUiConfigProperties config) {
    config.setValidatorUrl("none");
    return config;
  }

  @Override
  public void addViewControllers(ViewControllerRegistry registry) {
    registry.addViewController("/").setViewName("sign");
  }
}
