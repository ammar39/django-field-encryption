from django.conf import settings
from django.contrib import messages
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render

from django_field_encryption import FieldEncryptor

from .forms import DocumentForm, ProfileForm
from .models import Document, Profile


def index(request):
    """Homepage with stats and navigation."""
    context = {
        'profile_count': Profile.objects.count(),
        'document_count': Document.objects.count(),
        'active_key': getattr(settings, 'DATA_PROTECTION_ACTIVE_KEY_ID', 'not set'),
        'available_keys': list(getattr(settings, 'DATA_PROTECTION_KEYS', {}).keys()),
    }
    return render(request, 'showcase/index.html', context)


def profile_list(request):
    """List all profiles with encrypted fields."""
    profiles = Profile.objects.all()
    return render(request, 'showcase/profile_list.html', {'profiles': profiles})


def profile_create(request):
    """Create a new profile with encrypted fields."""
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            profile = form.save()
            messages.success(request, f'Profile "{profile.name}" created successfully!')
            return redirect('profile_detail', pk=profile.pk)
    else:
        form = ProfileForm()
    return render(
        request, 'showcase/profile_form.html', {'form': form, 'title': 'Create Profile'}
    )


def profile_detail(request, pk):
    """Show profile details including raw encrypted values."""
    profile = get_object_or_404(Profile, pk=pk)
    # Get the raw encrypted value from DB to show what it looks like
    raw_ssn = Profile.objects.filter(pk=pk).values_list('ssn', flat=True).first()
    raw_notes = Profile.objects.filter(pk=pk).values_list('notes', flat=True).first()
    raw_prefs = (
        Profile.objects.filter(pk=pk).values_list('preferences', flat=True).first()
    )

    context = {
        'profile': profile,
        'raw_ssn': raw_ssn,
        'raw_notes': raw_notes,
        'raw_preferences': raw_prefs,
    }
    return render(request, 'showcase/profile_detail.html', context)


def profile_edit(request, pk):
    """Edit an existing profile."""
    profile = get_object_or_404(Profile, pk=pk)
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=profile)
        if form.is_valid():
            profile = form.save()
            messages.success(request, f'Profile "{profile.name}" updated successfully!')
            return redirect('profile_detail', pk=profile.pk)
    else:
        form = ProfileForm(instance=profile)
    return render(
        request, 'showcase/profile_form.html', {'form': form, 'title': 'Edit Profile'}
    )


def profile_delete(request, pk):
    """Delete a profile."""
    profile = get_object_or_404(Profile, pk=pk)
    if request.method == 'POST':
        name = profile.name
        profile.delete()
        messages.success(request, f'Profile "{name}" deleted successfully!')
        return redirect('profile_list')
    return render(request, 'showcase/profile_confirm_delete.html', {'profile': profile})


def document_list(request):
    """List all documents with encrypted file storage."""
    documents = Document.objects.all()
    return render(request, 'showcase/document_list.html', {'documents': documents})


def document_upload(request):
    """Upload a new encrypted document."""
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save()
            messages.success(request, f'Document "{doc.title}" uploaded and encrypted!')
            return redirect('document_list')
    else:
        form = DocumentForm()
    return render(request, 'showcase/document_form.html', {'form': form})


def document_download(request, pk):
    """Download a decrypted document."""
    doc = get_object_or_404(Document, pk=pk)
    response = FileResponse(doc.file.open(), as_attachment=True, filename=doc.file.name)
    return response


def document_delete(request, pk):
    """Delete a document."""
    doc = get_object_or_404(Document, pk=pk)
    if request.method == 'POST':
        title = doc.title
        doc.delete()
        messages.success(request, f'Document "{title}" deleted successfully!')
        return redirect('document_list')
    return render(request, 'showcase/document_confirm_delete.html', {'document': doc})


def key_rotation(request):
    """Demo page for key rotation."""
    profiles = Profile.objects.all()
    active_key = getattr(settings, 'DATA_PROTECTION_ACTIVE_KEY_ID', 'not set')
    available_keys = list(getattr(settings, 'DATA_PROTECTION_KEYS', {}).keys())

    rotated_count = 0
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'rotate_all':
            for profile in Profile.objects.all():
                # Rotate each encrypted field
                if profile.ssn and FieldEncryptor.can_decrypt(profile.ssn):
                    rotated = FieldEncryptor.rotate_value(profile.ssn)
                    if rotated:
                        profile.ssn = rotated
                if profile.notes and FieldEncryptor.can_decrypt(profile.notes):
                    rotated = FieldEncryptor.rotate_value(profile.notes)
                    if rotated:
                        profile.notes = rotated
                if profile.preferences and FieldEncryptor.can_decrypt(
                    profile.preferences
                ):
                    rotated = FieldEncryptor.rotate_value(profile.preferences)
                    if rotated:
                        profile.preferences = rotated
                profile.save()
                rotated_count += 1
            messages.success(
                request,
                f'Rotated encryption keys for {rotated_count} profiles to {active_key}!',
            )
        elif action == 'switch_key':
            new_key = request.POST.get('new_key')
            if new_key in available_keys:
                settings.DATA_PROTECTION_ACTIVE_KEY_ID = new_key
                # Also need to clear cache
                FieldEncryptor.clear_cache()
                messages.success(request, f'Switched active key to {new_key}!')
            else:
                messages.error(request, 'Invalid key selected')
        return redirect('key_rotation')

    # Analyze key usage
    key_analysis = []
    for profile in profiles:
        ssn_key = (
            profile.ssn.split(':')[0] if profile.ssn and ':' in profile.ssn else 'none'
        )
        notes_key = (
            profile.notes.split(':')[0]
            if profile.notes and ':' in profile.notes
            else 'none'
        )
        prefs_key = (
            profile.preferences.split(':')[0]
            if profile.preferences and ':' in profile.preferences
            else 'none'
        )
        key_analysis.append(
            {
                'profile': profile,
                'ssn_key': ssn_key,
                'notes_key': notes_key,
                'prefs_key': prefs_key,
            }
        )

    context = {
        'profiles': profiles,
        'active_key': active_key,
        'available_keys': available_keys,
        'key_analysis': key_analysis,
        'rotated_count': rotated_count,
    }
    return render(request, 'showcase/key_rotation.html', context)
