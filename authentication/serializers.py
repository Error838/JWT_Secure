import re
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('name', 'email', 'password')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'validators': []},  # Disable email uniqueness check in response
        }

    def validate_email(self, value):
        # Ensure email contains '@gmail.com' domain
        if not re.match(r'^[^@]+@gmail\.com$', value):
            raise serializers.ValidationError('Only email addresses with @gmail.com domain are allowed.')
        return value

    def validate_password(self, value):
        # Ensure password contains at least 8 characters with at least one lowercase, one uppercase, one special character, and one number
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', value):
            raise serializers.ValidationError(
                'Password must be at least 8 characters long and contain at least one lowercase, one uppercase, one special character, and one number.'
            )
        return value

    def create(self, validated_data):
        email = validated_data['email']
        password = validated_data['password']

        if not re.match(r'^[^@]+@gmail\.com$', email):
            raise serializers.ValidationError('Only email addresses with @gmail.com domain are allowed.')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('A user with this email already exists.')

        user = User.objects.create_user(**validated_data)
        return user
