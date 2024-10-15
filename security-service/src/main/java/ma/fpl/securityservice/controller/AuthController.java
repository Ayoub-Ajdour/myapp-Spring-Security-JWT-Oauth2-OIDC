package ma.fpl.securityservice.controller;

import com.nimbusds.jwt.JWT;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private UserDetailsService userDetailsService;

    public AuthController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }
    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> jwtToken(String grantType,String username,String password,boolean withRefrechToken,String refrechToken) {
        String scope=null;
        String subject=null;
        if(grantType.equals("password")){
            Authentication authentication=authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username,password)
            );
            subject=authentication.getName();
            scope = authentication.getAuthorities()
                    .stream()
                    .map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));
        } else if (grantType.equals("refrechToken")) {
            if(refrechToken==null){
                return new ResponseEntity<>(Map.of("ErrorMessage","Refrech token is required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT= null;
            try {
                decodeJWT = jwtDecoder.decode(refrechToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("ErrorMessage","Refrech token is required"), HttpStatus.UNAUTHORIZED);
            }
            subject=decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scope=authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        }

        Instant instant = Instant.now();


        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefrechToken?5:30, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope", scope)
                .build();

        String jwtToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        Map<String, String> response = new HashMap<>();
        response.put("accessToken", jwtToken);
        if(withRefrechToken){
            JwtClaimsSet jwtClaimsSetRefrech = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();

            String jwtTokenRefrech = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefrech)).getTokenValue();
            response.put("RefrechToken", jwtTokenRefrech);
        }
//        return response;
          return new ResponseEntity<>(response,HttpStatus.OK);
    }


}
