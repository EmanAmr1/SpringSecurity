package com.spring.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {


    private static final String SECRET_KEY= "62df867f198c075a4d5381e8e7ea044acbe047b46d30e875f02562b594f05867";

    public String extractUsername(String token){
        return null;
    }



    private <T> T extractClaim(String token , Function<Claims ,T> claimsResolver){  // Function<Claims ,T> which takes a Claims object and returns an object of type T. This function is used to extract a specific claim from the Claims object.
        final Claims claims = extractAllClaims(token); //get all claims
        return claimsResolver.apply(claims); //extract any specific claim from token
    }






    private Claims extractAllClaims(String token){
        return Jwts               //is a utility class provided by the JJWT library to handle JWT operations

                .parserBuilder()  // This method starts the process of creating a parser for a JWT

                .setSigningKey(getSignInKey()) //This key must match the one used when the token was created.

                .build() //his method finalizes the configuration of the parser and returns a JwtParser

                .parseClaimsJws(token) //This method parses the JWT token string (token).
                                       // It validates the token's signature using the key set previously.
                                       // If the token is invalid or has expired, it will throw an exception. The result is a Jws<Claims>,
                                       // which contains the claims in the JWT

                .getBody(); //This method extracts and returns the claims body from the Jws<Claims>.
                            // The claims body is a map-like structure containing the JWT payload,
                            //which includes information such as the issuer, subject, expiration time, and any custom claims
    }


    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // decodes the SECRET_KEY string from Base64 encoding to a byte array
        //Decoders.BASE64 is a utility provided by the io.jsonwebtoken.impl library to handle Base64 decoding.
        return Keys.hmacShaKeyFor(keyBytes);
        //It takes the byte array and creates an HmacKey object suitable
        // for HMAC (Hash-based Message Authentication Code) operations with the SHA algorithm.
        // This key is used for signing and verifying the JWT's integrity and authenticity.
    }

}
