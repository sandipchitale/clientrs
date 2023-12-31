package sandipchitale.clientrs;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;

@SpringBootApplication
public class ClientrsApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientrsApplication.class, args);
	}
	
	@RestController
	public static class IndexController {
	    
	    @GetMapping("/")
	    public String index(Authentication authentication) {
	        return "User: "
					+ ((OAuth2AuthenticationToken)authentication).getPrincipal().getAttribute("sub")
					+ " Access token: "
					+ ((OAuth2AuthenticationToken)authentication).getPrincipal().getAttribute(OAuth2ParameterNames.ACCESS_TOKEN)
					+ " Refresh token: "
					+ ((OAuth2AuthenticationToken)authentication).getPrincipal().getAttribute(OAuth2ParameterNames.REFRESH_TOKEN)
					+ "!";
	    }
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
										   ClientRegistrationRepository clientRegistrationRepository,
										   @Qualifier("sharedSecretJwtDecoder") JwtDecoder jwtDecoder) throws Exception {

		ObjectPostProcessor<OAuth2LoginAuthenticationFilter> oAuth2LoginAuthenticationFilterPostProcessor = new ObjectPostProcessor<>() {
			@Override
			public <O extends OAuth2LoginAuthenticationFilter> O postProcess(O oAuth2LoginAuthenticationFilter) {
				oAuth2LoginAuthenticationFilter.setAuthenticationResultConverter(this::createAuthenticationResult);
				return oAuth2LoginAuthenticationFilter;
			}

			private OAuth2AuthenticationToken createAuthenticationResult(OAuth2LoginAuthenticationToken authenticationResult) {
					OAuth2User principal = authenticationResult.getPrincipal();

				if (principal instanceof DefaultOAuth2User defaultOAuth2User) {
					Map<String, Object> attributes = new LinkedHashMap<>(defaultOAuth2User.getAttributes());
					attributes.put(OAuth2ParameterNames.REFRESH_TOKEN, authenticationResult.getRefreshToken().getTokenValue());
					principal = new DefaultOAuth2User(defaultOAuth2User.getAuthorities(),
							Collections.unmodifiableMap(attributes),
							"sub");
				}

				return new OAuth2AuthenticationToken(principal, authenticationResult.getAuthorities(),
						authenticationResult.getClientRegistration().getRegistrationId());
			}
		};

		httpSecurity
				.authorizeHttpRequests((AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizationManagerRequestMatcherRegistry) -> {
					authorizationManagerRequestMatcherRegistry
							.anyRequest().authenticated();
				})
				.oauth2Login((OAuth2LoginConfigurer<HttpSecurity> httpSecurityOAuth2LoginConfigurer) -> {
					httpSecurityOAuth2LoginConfigurer.clientRegistrationRepository(clientRegistrationRepository);
					httpSecurityOAuth2LoginConfigurer.userInfoEndpoint(userInfoEndpointConfig -> {
						// This is to avoid user-info endpoint call
						userInfoEndpointConfig.userService(oauth2UserService(jwtDecoder));
					});
					httpSecurityOAuth2LoginConfigurer.withObjectPostProcessor(oAuth2LoginAuthenticationFilterPostProcessor);
				})
				.oauth2ResourceServer((OAuth2ResourceServerConfigurer<HttpSecurity> oauth2) -> {
					oauth2
							.jwt((OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwt) -> {
								// Use JWT decoder based on shared secret key to validate JWT tokens
								jwt.decoder(jwtDecoder);
							});
				});
		return httpSecurity.build();
	}

	// This is to avoid user-info endpoint call and instead build OAuth2User from JWT token
	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(JwtDecoder jwtDecoder) {
		return new DefaultOAuth2UserService() {
			@Override
			public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
				Jwt accessTokenJwt = jwtDecoder.decode(userRequest.getAccessToken().getTokenValue());
				Map<String, Object> claims = new HashMap<>(accessTokenJwt.getClaims());
				claims.put(OAuth2ParameterNames.ACCESS_TOKEN, accessTokenJwt.getTokenValue());
				return new DefaultOAuth2User(Collections.emptyList(), claims, "sub");
			}
		};
	}

	@Bean
	@Qualifier("sharedSecretJwtDecoder")
	public JwtDecoder jwtDecoder(@Value("${jwt.shared-secret-key}") String sharedSecretKey) {
		NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(new SecretKeySpec(sharedSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256")).build();
		nimbusJwtDecoder.setJwtValidator(
				new DelegatingOAuth2TokenValidator<>(
						new JwtTimestampValidator(Duration.of(30, ChronoUnit.SECONDS)))); // 30 seconds clock skew
		return nimbusJwtDecoder;
	}
}
