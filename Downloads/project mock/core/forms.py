"""
forms.py — Luxelle Ecommerce (app: core)
All Django forms for authentication, profile, and address management.
"""

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone

from .models import CustomUser, UserProfile, Address


# ─────────────────────────────────────────────
# Reusable widget helpers
# ─────────────────────────────────────────────

def _input(placeholder, type_="text", extra_classes=""):
    return forms.TextInput(attrs={
        "placeholder": placeholder,
        "class": f"form-control {extra_classes}",
        "autocomplete": "off",
    })


def _email(placeholder):
    return forms.EmailInput(attrs={"placeholder": placeholder, "class": "form-control"})


def _password(placeholder):
    return forms.PasswordInput(attrs={"placeholder": placeholder, "class": "form-control"}, render_value=False)


# ─────────────────────────────────────────────
# Registration Form
# ─────────────────────────────────────────────

class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Password",
        widget=_password("Create a password"),
        validators=[validate_password],
        help_text="Minimum 8 characters.",
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=_password("Confirm your password"),
    )

    class Meta:
        model = CustomUser
        fields = ["first_name", "last_name", "email", "phone"]
        widgets = {
            "first_name": _input("First name"),
            "last_name":  _input("Last name"),
            "email":      _email("Email address"),
            "phone":      _input("Phone number", type_="tel"),
        }

    def clean_email(self):
        email = self.cleaned_data.get("email", "").lower()
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get("phone", "").strip()
        if phone and not phone.replace("+", "").isdigit():
            raise ValidationError("Enter a valid phone number.")
        return phone

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Passwords do not match.")
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.is_active = False  # Stays inactive until OTP verified
        if commit:
            user.save()
        return user


# ─────────────────────────────────────────────
# Login Form
# ─────────────────────────────────────────────

class LoginForm(forms.Form):
    email = forms.EmailField(
        widget=_email("Email address"),
        label="Email",
    )
    password = forms.CharField(
        widget=_password("Password"),
        label="Password",
    )

    def clean_email(self):
        return self.cleaned_data.get("email", "").lower()


# ─────────────────────────────────────────────
# OTP Verification Form
# ─────────────────────────────────────────────

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        max_length=6,
        min_length=6,
        label="OTP",
        widget=forms.TextInput(attrs={
            "placeholder": "Enter 6-digit OTP",
            "class": "form-control otp-input",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
            "maxlength": "6",
        }),
    )

    def clean_otp(self):
        otp = self.cleaned_data.get("otp", "").strip()
        if not otp.isdigit():
            raise ValidationError("OTP must contain digits only.")
        return otp


# ─────────────────────────────────────────────
# Forgot Password Form
# ─────────────────────────────────────────────

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        widget=_email("Registered email address"),
        label="Email",
    )

    def clean_email(self):
        email = self.cleaned_data.get("email", "").lower()
        if not CustomUser.objects.filter(email=email, is_active=True).exists():
            raise ValidationError("No active account found with this email.")
        return email

class SetNewPasswordForm(forms.Form):
    new_password = forms.CharField(
        label="New Password",
        widget=_password("New password"),
        validators=[validate_password],
    )
    confirm_password = forms.CharField(
        label="Confirm Password",
        widget=_password("Confirm new password"),
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("new_password")
        p2 = cleaned.get("confirm_password")
        if p1 and p2 and p1 != p2:
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned

class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(
        label="Current Password",
        widget=_password("Current password"),
    )
    new_password = forms.CharField(
        label="New Password",
        widget=_password("New password"),
        validators=[validate_password],
    )
    confirm_password = forms.CharField(
        label="Confirm New Password",
        widget=_password("Confirm new password"),
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_current_password(self):
        current = self.cleaned_data.get("current_password")
        if not self.user.check_password(current):
            raise ValidationError("Current password is incorrect.")
        return current

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("new_password")
        p2 = cleaned.get("confirm_password")
        if p1 and p2 and p1 != p2:
            self.add_error("confirm_password", "Passwords do not match.")
        # Ensure new password differs from current
        if p1 and self.user.check_password(p1):
            self.add_error("new_password", "New password must be different from the current password.")
        return cleaned

class EmailChangeForm(forms.Form):
    new_email = forms.EmailField(
        label="New Email",
        widget=_email("New email address"),
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_new_email(self):
        email = self.cleaned_data.get("new_email", "").lower()
        if CustomUser.objects.filter(email=email).exclude(pk=self.user.pk).exists():
            raise ValidationError("This email is already in use by another account.")
        return email


# ─────────────────────────────────────────────
# Profile Edit Forms

class ProfileEditForm(forms.ModelForm):
    full_name = forms.CharField(
        label="Full Name",
        widget=_input("Enter your full name"),
        required=True
    )

    class Meta:
        model = CustomUser
        fields = ["full_name", "email", "phone"]
        widgets = {
            "email":      _email("Email address"),
            "phone":      _input("Phone number", type_="tel"),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["full_name"].initial = self.instance.get_full_name()

    def clean_full_name(self):
        name = self.cleaned_data.get("full_name", "").strip()
        if len(name) < 2:
            raise ValidationError("Name must be at least 2 characters.")
        if not all(ch.isalpha() or ch.isspace() for ch in name):
            raise ValidationError("Name can only contain alphabets and spaces.")
        return name

    def clean_phone(self):
        phone = self.cleaned_data.get("phone", "").strip()
        if not phone.isdigit():
            raise ValidationError("Phone must contain digits only.")
        if len(phone) != 10:
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

    def clean_email(self):
        email = self.cleaned_data.get("email", "").lower()
        qs = CustomUser.objects.filter(email=email)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("This email is already in use by another user.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        full_name = self.cleaned_data.get("full_name", "").strip()
        parts = full_name.split(maxsplit=1)
        if len(parts) == 2:
            user.first_name = parts[0]
            user.last_name = parts[1]
        else:
            user.first_name = full_name
            user.last_name = ""
        if commit:
            user.save()
        return user
# ─────────────────────────────────────────────




class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ["avatar", "gender", "date_of_birth", "bio"]
        widgets = {
            "gender": forms.Select(attrs={"class": "form-control"}),
            "date_of_birth": forms.DateInput(
                attrs={"class": "form-control", "type": "date"}
            ),
            "bio": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "Write a short bio…",
                "maxlength": 300,
            }),
            "avatar": forms.FileInput(attrs={"class": "form-control", "accept": "image/*"}),
        }

    def clean_avatar(self):
        avatar = self.cleaned_data.get("avatar")
        if avatar and hasattr(avatar, "size"):
            if avatar.size > 2 * 1024 * 1024:
                raise ValidationError("Image must be under 2 MB.")
            allowed = ["image/jpeg", "image/png", "image/webp"]
            if hasattr(avatar, "content_type") and avatar.content_type not in allowed:
                raise ValidationError("Only JPEG, PNG, or WebP images are allowed.")
        return avatar


# ─────────────────────────────────────────────
# Address Form
# ─────────────────────────────────────────────

class AddressForm(forms.ModelForm):
    class Meta:
        model = Address
        fields = [
            "full_name", "phone", "address_line1", "address_line2",
            "city", "state", "postal_code", "country",
            "address_type", "is_default",
        ]
        widgets = {
            "full_name":     _input("Full name"),
            "phone":         _input("Phone number", type_="tel"),
            "address_line1": _input("Street address"),
            "address_line2": _input("Apartment, suite, etc. (optional)"),
            "city":          _input("City"),
            "state":         _input("State / Province"),
            "postal_code":   _input("Postal / ZIP code"),
            "country":       _input("Country"),
            "address_type":  forms.Select(attrs={"class": "form-control"}),
            "is_default":    forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def clean_full_name(self):
        name = self.cleaned_data.get("full_name", "").strip()
        if len(name) < 2:
            raise ValidationError("Full name must be at least 2 characters.")
        if not all(ch.isalpha() or ch.isspace() for ch in name):
            raise ValidationError("Full name can only contain letters and spaces — no special characters.")
        return name

    def clean_phone(self):
        phone = self.cleaned_data.get("phone", "").strip()
        # Allow optional leading +91 or 0 for Indian numbers, then 10 digits
        digits = phone.replace("+", "").replace(" ", "").replace("-", "")
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        if not digits.isdigit():
            raise ValidationError("Phone number must contain digits only.")
        if len(digits) != 10:
            raise ValidationError("Phone number must be exactly 10 digits.")
        return digits

    def clean_address_line1(self):
        value = self.cleaned_data.get("address_line1", "").strip()
        if len(value) < 5:
            raise ValidationError("Street address must be at least 5 characters.")
        # Block dangerous characters
        forbidden = ["<", ">", "{", "}", "|", "\\", "^", "`"]
        if any(c in value for c in forbidden):
            raise ValidationError("Address contains invalid characters.")
        return value

    def clean_city(self):
        city = self.cleaned_data.get("city", "").strip()
        if len(city) < 2:
            raise ValidationError("City name must be at least 2 characters.")
        if not all(ch.isalpha() or ch.isspace() or ch == "-" for ch in city):
            raise ValidationError("City name can only contain letters, spaces, or hyphens.")
        return city

    def clean_state(self):
        state = self.cleaned_data.get("state", "").strip()
        if len(state) < 2:
            raise ValidationError("State/Province must be at least 2 characters.")
        if not all(ch.isalpha() or ch.isspace() or ch == "-" for ch in state):
            raise ValidationError("State name can only contain letters, spaces, or hyphens.")
        return state

    def clean_country(self):
        country = self.cleaned_data.get("country", "").strip()
        if len(country) < 2:
            raise ValidationError("Country name must be at least 2 characters.")
        if not all(ch.isalpha() or ch.isspace() for ch in country):
            raise ValidationError("Country name can only contain letters and spaces.")
        return country

    def clean_postal_code(self):
        code = self.cleaned_data.get("postal_code", "").strip()
        if not code.isdigit():
            raise ValidationError("Postal code must contain digits only.")
        if len(code) < 4 or len(code) > 10:
            raise ValidationError("Postal code must be between 4 and 10 digits.")
        return code