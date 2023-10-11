package lol.rafadev.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lol.rafadev.todolist.user.IUserRepository;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

      var authorization = request.getHeader("Authorization");
      System.out.println(authorization);

      var authDecoded = authorization.substring("Basic".length()).trim();

      byte[] authDecode = Base64.getDecoder().decode(authDecoded);

      var authString = new String(authDecode);

      String[] credencials = authString.split(":");

      String username = credencials[0];
      String password = credencials[1];

      var user = this.userRepository.findByUsername(username);

      if(user == null) {
        response.sendError(401, "Parabens! Você não tem autorização.");
      } else {

        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

        if(passwordVerify.verified) {
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401);
        }

      }


    
  }

 
  
}
