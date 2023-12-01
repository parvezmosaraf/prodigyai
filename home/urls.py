from django.contrib import admin
from django.urls import path
from .import views
from django.contrib import admin
from django.urls import path
from .import views
from django.contrib import admin
from django.urls import path,include



urlpatterns = [
    path('',views.home,name="home"),
    path('cv_form',views.cv_form,name="cv_form"),
    path('search_pdf',views.search_pdf,name="search_pdf"),
    path('search_attachments',views.search_attachments,name="search_attachments"),
    path('signin', views.signin, name="signin"),
    path('signup/', views.signup, name="signup"),
    path('signout/', views.signout, name="signout"),
    
    
]