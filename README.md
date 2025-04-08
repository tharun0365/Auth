# Auth
install:
pip install djangorestframework

INSTALLED_APPS = [
    ...
    'rest_framework',
]

pip install djangorestframework
pip install djangorestframework-authtoken

also add in installed apps 'rest_framework.authtoken',

in app level:
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns += [
    path('api-token-auth/', obtain_auth_token),
]

FOR more secure:
pip install djangorestframework-simplejwt

app level:
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns += [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]



views.py
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404

from .models import Snippet
from .serializers import SnippetSerializer, RegisterSerializer, UserSerializer


# Snippet List - Anyone can GET, only authenticated can POST
@api_view(['GET', 'POST'])
def snippet_list(request):
    if request.method == 'GET':
        snippets = Snippet.objects.all()
        serializer = SnippetSerializer(snippets, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required to create a snippet."},
                            status=status.HTTP_401_UNAUTHORIZED)

        serializer = SnippetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Snippet Detail - Anyone can GET, only owner can PUT/DELETE
@api_view(['GET', 'PUT', 'DELETE'])
def snippet_detail(request, pk):
    snippet = get_object_or_404(Snippet, pk=pk)

    if request.method == 'GET':
        serializer = SnippetSerializer(snippet)
        return Response(serializer.data)

    elif request.method == 'PUT':
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED)
        if snippet.owner != request.user:
            return Response({"detail": "You don't have permission to update this snippet."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = SnippetSerializer(snippet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED)
        if snippet.owner != request.user:
            return Response({"detail": "You don't have permission to delete this snippet."},
                            status=status.HTTP_403_FORBIDDEN)

        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Register new users
@api_view(['POST'])
def register_user(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# List all users (Only for logged-in users)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_list(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


serializer.py
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Snippet


# Snippet Serializer
class SnippetSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')  # Show owner's username

    class Meta:
        model = Snippet
        fields = ['id', 'title', 'code', 'created', 'owner']  # Adjust fields based on your Snippet model


# User Registration Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email'),
            password=validated_data['password']
        )
        return user


# User List Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


urls.py/app
from django.urls import path
from . import views

urlpatterns = [
    # Snippet endpoints
    path('snippets/', views.snippet_list, name='snippet-list'),
    path('snippets/<int:pk>/', views.snippet_detail, name='snippet-detail'),

    # User registration
    path('register/', views.register_user, name='register'),

    # User list (protected)
    path('users/', views.user_list, name='user-list'),
]

urls.py/project 
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('your_app_name.urls')),  # your app's API endpoints
    path('api-auth/', include('rest_framework.urls')),  # <-- this enables login/logout on browsable API
]

settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ]
}

