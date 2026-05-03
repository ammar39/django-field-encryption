from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('profiles/', views.profile_list, name='profile_list'),
    path('profiles/create/', views.profile_create, name='profile_create'),
    path('profiles/<int:pk>/', views.profile_detail, name='profile_detail'),
    path('profiles/<int:pk>/edit/', views.profile_edit, name='profile_edit'),
    path('profiles/<int:pk>/delete/', views.profile_delete, name='profile_delete'),
    path('documents/', views.document_list, name='document_list'),
    path('documents/upload/', views.document_upload, name='document_upload'),
    path(
        'documents/<int:pk>/download/',
        views.document_download,
        name='document_download',
    ),
    path('documents/<int:pk>/delete/', views.document_delete, name='document_delete'),
    path('key-rotation/', views.key_rotation, name='key_rotation'),
]
