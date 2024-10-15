package ma.fpl.securityservice.controller;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
@ConfigurationProperties(prefix = "rsa")
public record Rsakeysconfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}
