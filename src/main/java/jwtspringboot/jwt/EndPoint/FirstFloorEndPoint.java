package jwtspringboot.jwt.EndPoint;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/floor1")

public class FirstFloorEndPoint {
    @GetMapping("office1")
    //@PreAuthorize("hasAnyRole('USER')")
public ResponseEntity<?> enterOffice1(){
        SecurityContextHolder.getContext().getAuthentication();
    return new ResponseEntity<Object>("You are granted to access 1st Office", HttpStatus.OK);
}
@GetMapping("office2")
@PreAuthorize("hasAnyRole('ADMIN')")
public ResponseEntity<?> enterOffice2(){
    return new ResponseEntity<Object>("You are granted to access 2end Office", HttpStatus.OK);
}
}
