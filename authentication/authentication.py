from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication

class JWTTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        jwt_token_user_authentication = JWTTokenUserAuthentication()

        user = jwt_token_user_authentication.authenticate(request)
        if not user:
            raise AuthenticationFailed('Invalid or missing JWT token.')

        return (user, None)
