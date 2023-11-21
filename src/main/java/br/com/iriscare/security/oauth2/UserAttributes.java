package br.com.iriscare.security.oauth2;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserAttributes {

    private String name;
    private List<String> grantedAuthorities;
    private Map<String, Object> userAttributes;


}
