package ma.fpl.securityservice.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {

    @GetMapping("/getdata")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_USER')")
    public Map<String,Object> dataTest(Authentication auth){
        return Map.of("Message","Data Test","username",auth.getName(),"ROLE",auth.getAuthorities());
    }
    @PostMapping("/savedata")
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public Map<String,String> savedata(Authentication auth){
        return Map.of("message","Data Saved");
    }
}
