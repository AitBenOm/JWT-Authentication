package jwtspringboot.jwt.service;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService{
    @Override
    public  UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        jwtspringboot.jwt.Model.User user= loadUserByUserName(userName);
        return new User(user.getUserNmae(),user.getPassword(),
                AuthorityUtils.createAuthorityList("ROLE_USER"));//
    }

    public static jwtspringboot.jwt.Model.User loadUserByUserName(String userName){
        return new jwtspringboot.jwt.Model.User("batman", "12345");
    }
}
