from rest_framework import serializers
from .models import Songs


class SongsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Songs
        fields = '__all__'

class TokenSerializer(serializers.Serializer):
    """
    This serializes token data
    """
    token = serializers.CharField(max_length=255)

