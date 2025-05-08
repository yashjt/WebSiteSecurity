from django.db import models
# Create your models here.


class Admin1(models.Model):
    admin_id = models.AutoField(primary_key=True)
    admin_name = models.CharField(max_length=50)
    password = models.CharField(max_length=8)

    def __str__(self):
        return self.admin_id
    

class Customer(models.Model):
    customer_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    email = models.CharField(max_length=50)
    password = models.CharField(max_length=8)

    def __str__(self):
        return self.name


class WebsiteTraffic(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.URLField()
    visits = models.PositiveIntegerField(default=0)
    last_checked = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return self.url
    
class Website(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.URLField()
    status_code = models.PositiveIntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
    
class PingResult(models.Model):
    website_url = models.URLField(max_length=200)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_online = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.website_url
    
class ScannedWebsite(models.Model):
    url = models.URLField()
    scan_result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url


class ShortenedURL(models.Model):
    long_url = models.URLField()
    short_code = models.CharField(max_length=10, unique=True)

    def __str__(self):
        return self.long_url


    
class ScannedWebsite(models.Model):
    url = models.URLField()
    scan_result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url



class Vulnerability(models.Model):
    url = models.URLField()
    method = models.CharField(max_length=10)
    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Vulnerability detected at {self.url}"
    
    
class ScannedURL(models.Model):
    url = models.URLField()
    is_vulnerable = models.BooleanField(default=False)
    scan_result = models.TextField(blank=True)

    def __str__(self):
        return self.url
    

class CSFScannerResult(models.Model):
    url = models.URLField(max_length=255)
    is_vulnerable = models.BooleanField()

    def __str__(self):
        return self.url
    
    
    

class SQLInjectionResult(models.Model):
    url = models.URLField(max_length=200)
    is_vulnerable = models.BooleanField(default=False)
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url    
    


class NmapScanResult(models.Model):
    target_url = models.URLField()
    scan_result = models.TextField()
    
    
    def __str__(self):
        return self.target_url
    


class OWASPSecurityScan(models.Model):
    target_url = models.URLField()
    scan_result = models.TextField()
    scan_date = models.DateTimeField(auto_now_add=True)
    

class SQLInjectionScanResult(models.Model):
    url = models.URLField()
    is_vulnerable = models.BooleanField(default=False)
    scan_time = models.DateTimeField(auto_now_add=True)
    
class Contact(models.Model):
    cno = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250)
    email = models.CharField(max_length=250)
    content = models.TextField()
    
    def __str__(self):
        return self.cno
    
    