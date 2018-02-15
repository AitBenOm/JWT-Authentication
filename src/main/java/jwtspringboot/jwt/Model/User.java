package jwtspringboot.jwt.Model;

public class User {

    private String userNmae;
    private String password;

    public User() {
    }

    public User(String userNmae, String password) {
        this.userNmae = userNmae;
        this.password = password;
    }

    public String getUserNmae() {
        return userNmae;
    }

    public void setUserNmae(String userNmae) {
        this.userNmae = userNmae;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
