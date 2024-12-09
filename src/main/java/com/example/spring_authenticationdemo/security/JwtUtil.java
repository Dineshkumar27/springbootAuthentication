package com.example.spring_authenticationdemo.security;

import com.example.spring_authenticationdemo.entity.Role;
import com.example.spring_authenticationdemo.entity.User;
import com.example.spring_authenticationdemo.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    //secretKey
    private static final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    private final int jwtExpirationTimeMs=864000000;

    private UserRepository userRepository;

    public JwtUtil(UserRepository userRepository){
        this.userRepository=userRepository;
    }

    public String generateToken(String userName) {
        Optional<User> user = userRepository.findByUsername(userName);
        Set<Role> roles = user.get().getRoles();

        //Add roles to the token

        return Jwts.builder().setSubject(userName).claim("roles", roles.stream()
                        .map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime() + jwtExpirationTimeMs*10))
                .signWith(secretKey).compact();
    }
        //Extract User Name
    public String extractUserName(String token){
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }
    //Extract Roles
    public Set<String> extractRoles(String token){
        String rolesString=Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().get("roles",String.class);
        return Set.of(rolesString);
    }

    //token validation

    public boolean isValidToken(String token){
        try {
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        }catch (JwtException|IllegalArgumentException e){
            return false;
        }
    }

}
