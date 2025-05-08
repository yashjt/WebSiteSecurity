from django import forms

class WebsiteForm(forms.Form):
    url = forms.URLField(label='Website URL')
    
    

class ScanForm(forms.Form):
    url = forms.URLField(label='Enter URL to scan for XSS vulnerabilities')
    
    

class CSFScannerForm(forms.Form):
    url = forms.URLField(label='Enter URL:', required=True)
    
 
class SQLInjectionScannerForm(forms.Form):
    url = forms.URLField(label='Enter URL to Scan for SQL Injection', max_length=255)    
    
class SQLInjectionForm(forms.Form):
    url = forms.URLField(label='Enter URL to Scan', max_length=200)
    
    
    
class NmapScanForm(forms.Form):
    target_url = forms.URLField(label='Enter Target URL')
    


class OWASPSecurityScanForm(forms.Form):
    target_url = forms.URLField(label='Enter Target URL')
    
    