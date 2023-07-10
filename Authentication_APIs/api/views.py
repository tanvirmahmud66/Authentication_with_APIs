from django.contrib.auth import authenticate

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, ChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from .renderers import UserRenderer


#----------------------------------------- Manually Token for User
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


#============================================= User Registration api view
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
         serializer = UserRegistrationSerializer(data=request.data)
         if serializer.is_valid(raise_exception=True):
              user = serializer.save()
              token = get_tokens_for_user(user)
              return Response({
                   "msg": "User Created Successfully",
                   "token": token,
                   "data": serializer.data,
                   "status": status.HTTP_201_CREATED,
              }, status=status.HTTP_201_CREATED)
         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#============================================ User Login
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                    "msg": "User Login Successfull",
                    "token": token,
                    "status": status.HTTP_200_OK,
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": {'non_field_errors': ['Email or Password is not valid']}
                }, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 
    

#========================================== Profile
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

#========================================== Change Password
class ChangePassword(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({
                "msg": "Password Changed Successfully",
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#=========================================== Send Password Reset Email
class SendPasswordResetEmail(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                "msg":"Password Reset Link Send. Please Check Your Email",
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

#=========================================== User Password Reset View
class UserResetPassword(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token):
        serializer = UserPasswordResetSerializer(data=request.data, context = {"uid": uid,"token": token,})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":"Password Reset Successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)