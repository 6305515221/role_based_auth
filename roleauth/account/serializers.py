from rest_framework import serializers
from .models import CustomUser

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    role = serializers.CharField(required=False)
    secret_key = serializers.CharField(required=False)




class SignupSerializer(serializers.ModelSerializer):
    secret_key = serializers.CharField(write_only=True, required=False)
    role = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'role', 'secret_key']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        role = data.get('role', 'User')
        secret_key = data.get('secret_key', '')

        # Validate secret keys for Admin and SuperAdmin
        if role == 'Admin' and secret_key != 'admin@123':
            raise serializers.ValidationError({'secret_key': 'Invalid Admin secret key'})
        if role == 'SuperAdmin' and secret_key != 'super@123':
            raise serializers.ValidationError({'secret_key': 'Invalid SuperAdmin secret key'})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        secret_key = validated_data.pop('secret_key', None)  # Remove before saving
        role = validated_data.get('role', 'User')

        user = CustomUser(**validated_data)
        user.set_password(password)
        user.role = role
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'role']

class adminSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'role']
        # read_only_fields = ['id', 'username', 'role']