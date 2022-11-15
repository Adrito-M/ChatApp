from django.urls import path
from . import views, consumers

urlpatterns = [
    path('', views.index),
    path('login', views.login),
    path('register', views.register),
    path('dashboard', views.dashboard),
    path('api/dfh', views.dfh),
    path('api/validateusername', views.validateusername),
]

websocket_urlpatterns = [
    path('ws/chat/user', consumers.UserChatConsumer.as_asgi()),
]