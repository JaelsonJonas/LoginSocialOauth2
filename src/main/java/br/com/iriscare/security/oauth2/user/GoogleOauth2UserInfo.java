package br.com.iriscare.security.oauth2.user;

import java.util.Map;

public class GoogleOauth2UserInfo extends OAuth2UserInfo {


    public GoogleOauth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
