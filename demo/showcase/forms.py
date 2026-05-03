from django import forms

from .models import Profile, Document


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['name', 'email', 'ssn', 'notes', 'preferences']
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 4}),
            'preferences': forms.Textarea(
                attrs={
                    'rows': 4,
                    'placeholder': '{"theme": "dark", "notifications": true}',
                }
            ),
        }

    def clean_preferences(self):
        data = self.cleaned_data['preferences']
        if data is None:
            return {}
        if isinstance(data, str):
            import json

            try:
                return json.loads(data)
            except json.JSONDecodeError:
                raise forms.ValidationError('Invalid JSON format')
        return data


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
