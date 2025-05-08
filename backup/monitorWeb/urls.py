# monitor/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('index/' , views.index , name='index'),
    path('about/' , views.about , name='about'),
    path('contact/', views.contact , name='contact'),
    # path('contact_form/' , views.contact_form , name='contact_form'),
    path('home/', views.home, name='home'),
    path('add_website/', views.add_website, name='add_website'),
    # path('ping_form/', views.ping_form , name="ping_form"),
    path('ping/', views.ping_website, name='ping_website'),
    path('ping_results/', views.ping_results, name='ping_results'),
    path('pingCommand/', views.ping_url , name="ping_url"),
    path('pingScanner/', views.ping_scanner , name="ping_scanner"),
    path('port/' , views.scan_ports , name="scan_ports"),
    path('bitlilink/', views.shorten_or_resolve_url, name='shorten_url'),
    # # path('<str:short_code>/', views.resolve_url, name='resolve_url'),
    # path('initiate-scan/', views.initiate_scan, name='initiate_scan'),
    # path('scanned-websites/', views.list_scanned_websites, name='list_scanned_websites'),
    # path('scan-result/<int:website_id>/', views.view_scan_result, name='view_scan_result'),
    # Css 
    path('xss/' , views.xss_scanner , name='xss_scanner'),
    path('monitor/', views.website_monitoring, name='monitor_website'),
    path('user_page/', views.user_page , name='user_page'),
    path('login/' , views.login , name='login'),
    path('register/' , views.register , name='register'),
    path('logout_view/', views.logout_view, name='logout_view'),
    path('info/', views.info , name='info'),
    # sql injection 
    path('scan/', views.sql_injection_scan, name='sql_injection_scan'),
    # path('sql-injection/', views.sql_injection_scanner, name='sql_injection_scanner'),
    path('sqlInjection/', views.sql_injection_scanner , name='sql_injection_scanner'),
    # csrf 
    path('csrf-scan/', views.csrf_scanner, name='csrf_scanner'),
    #NMAP
  
    # Admin 
    path('Adminlogin/', views.AdminDashboard , name='AdminDashboard'),
    path('scanned-websites/', views.scanned_website_list, name='scanned_website_list'),
    path('websiteList/' , views.website_list , name='website_list'),
    path("abitlilink/" , views.Abitlilink , name='Abitlilink'),
    path('customerList/' , views.customer_list , name='customer_list'),
    path('xssList/' , views.xss_List , name='xss_List'),
    path('csrfList/' ,views.csrf_list ,  name="csrf_list"),
    path('sqlList/', views.sqlList , name="sqlList"),
    
    # delete code 
    path('xss-delete/<int:scan_id>/', views.delete_xss_scan, name='delete_xss_scan'),
    path('customer_delete/<int:cust_id>/', views.customer_Delete , name='customer_Delete'),
    path('website_delete/<int:w_id>/', views.del_website , name='del_website'),
    path('delete_bit/<int:b_id>/', views.del_bit , name='del_bit'),
    path('csrfDel/<int:cr_id>/', views.csrfDel , name="csrfDel"),
    path('sql_del/<int:sql_id>/', views.sql_del , name='sql_del'  ),
]
