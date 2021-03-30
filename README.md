# java-sample
Java Sample app for K8s testing

The main branch of this application is just a simple Hello World endpoint.

There are 3 other branches which contain different implementations of OAuth2 Security implementations customized for KeyCloak roles

#oauth2-preauthorized-token
This branch assumes an existing Jwt token is included in the `X-Forwarded-Access-Token` this is passed to this endpoint from an oauth2-proxy sidecar in a k8s environment.
You can find the deployment artifacts in the `oauth2-proxy-with-keycloak` folder and branch of the [cks-cluster project](https://github.com/pksheldon4/cks-cluster)

#oauth2-resource-server
This version is a pure resource server with Keycloak as an Auth Provider. It contains a Keycloak specific Role Converter to convert Realm and/or Client roles into Granted Authorities for the User.
Use along with [Oauth2 Gateway](https://github.com/pksheldon4/oauth2-gateway) for Oauth2 Client login and routing.



#oauth2login-with-keycloak-roles
The branch demonstrates a single application which handles the oauth2login and resource server using a custom Keycloak OAuth2UserService to convert the jwt token to ROLE GrantedAuthorities.