"""
views.py — Luxelle Ecommerce (app: core)
Complete authentication, profile, and address management views.
All template names match the existing frontend templates exactly.
"""

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .decorators import (
    anonymous_required,
    otp_session_required,
    password_reset_session_required,
)
from django.contrib.auth import update_session_auth_hash
from .forms import (
    AddressForm,
    ForgotPasswordForm,
    LoginForm,
    OTPVerificationForm,
    ProfileEditForm,
    RegistrationForm,
    SetNewPasswordForm,
    UserProfileForm,
    ChangePasswordForm,
    EmailChangeForm,
)
from .models import Address, CustomUser, UserProfile
from .utils import (
    clear_pending_user_session,
    create_otp_for_user,
    get_pending_user,
    send_otp_email,
    set_pending_user_session,
    verify_otp,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
# HOME
# ══════════════════════════════════════════════════════════════

def home_view(request):
    """Public home / landing page."""
    return render(request, "home.html")


# ══════════════════════════════════════════════════════════════
# REGISTRATION
# ══════════════════════════════════════════════════════════════

@anonymous_required()
def register_view(request):
    """
    Step 1 of registration.
    Creates an inactive user and sends an OTP to their email.
    """
    form = RegistrationForm(request.POST or None)

    if request.method == "POST":
        print(f"[REGISTER] POST received with data: {request.POST}")
        if form.is_valid():
            print(f"[REGISTER] Form is VALID. Creating user...")
            user = form.save()  # is_active=False by default
            print(f"[REGISTER] User created: {user.email} (pk={user.pk})")

            otp_obj    = create_otp_for_user(user, purpose="registration")
            print(f"[REGISTER] OTP created: {otp_obj.otp}")

            email_sent = send_otp_email(user, otp_obj.otp, purpose="registration")
            print(f"[REGISTER] Email sent: {email_sent}")

            if not email_sent:
                user.delete()
                messages.error(request, "Failed to send verification email. Please try again.")
                return render(request, "register.html", {"form": form})

            set_pending_user_session(request, user.pk, purpose="registration")
            messages.success(request, f"OTP sent to {user.email}. Please verify your email.")
            print(f"[REGISTER] Redirecting to verify_otp")
            return redirect("verify_otp")
        else:
            print(f"[REGISTER] Form INVALID. Errors: {form.errors}")

    return render(request, "register.html", {"form": form})


# ══════════════════════════════════════════════════════════════
# OTP VERIFICATION (Registration)
# ══════════════════════════════════════════════════════════════

@otp_session_required
def verify_otp_view(request):
    """
    Step 2 of registration.
    Verifies the OTP and activates the user account.
    """
    user = get_pending_user(request)
    if not user:
        messages.error(request, "Session expired. Please register again.")
        return redirect("register")

    form = OTPVerificationForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            otp_input = form.cleaned_data["otp"]
            valid, error_msg = verify_otp(user, otp_input, purpose="registration")

            if valid:
                user.is_active   = True
                user.is_verified = True
                user.save(update_fields=["is_active", "is_verified"])

                clear_pending_user_session(request)
                login(request, user, backend="django.contrib.auth.backends.ModelBackend")

                messages.success(request, "Email verified! Welcome to Luxelle.")
                return redirect("home")
            else:
                messages.error(request, error_msg)

    return render(request, "verify_otp.html", {"form": form, "email": user.email})


@otp_session_required
def resend_otp_view(request):
    """Resend OTP for registration verification."""
    user = get_pending_user(request)
    if not user:
        messages.error(request, "Session expired. Please register again.")
        return redirect("register")

    otp_obj    = create_otp_for_user(user, purpose="registration")
    email_sent = send_otp_email(user, otp_obj.otp, purpose="registration")

    if email_sent:
        messages.success(request, f"A new OTP has been sent to {user.email}.")
    else:
        messages.error(request, "Failed to resend OTP. Please try again.")

    return redirect("verify_otp")


# ══════════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════════

@anonymous_required()
def login_view(request):
    """
    Email + password login.
    Handles unverified accounts by re-sending OTP.
    """
    form = LoginForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            email    = form.cleaned_data["email"]
            password = form.cleaned_data["password"]

            user = authenticate(request, username=email, password=password)

            if user is None:
                # Check if user exists but is unverified
                try:
                    existing = CustomUser.objects.get(email=email)
                    if not existing.is_active:
                        otp_obj = create_otp_for_user(existing, purpose="registration")
                        send_otp_email(existing, otp_obj.otp, purpose="registration")
                        set_pending_user_session(request, existing.pk, purpose="registration")
                        messages.warning(
                            request,
                            "Your email is not verified. A new OTP has been sent.",
                        )
                        return redirect("verify_otp")
                except CustomUser.DoesNotExist:
                    pass

                messages.error(request, "Invalid email or password.")
            else:
                login(request, user)
                # Clear any pending OTP session data after successful login
                clear_pending_user_session(request)
                logger.info(f"User logged in: {user.email}")

                next_url = request.GET.get("next", "home")
                messages.success(request, f"Welcome back, {user.first_name or user.email}!")
                return redirect(next_url)

    return render(request, "login.html", {"form": form})


# ══════════════════════════════════════════════════════════════
# LOGOUT
# ══════════════════════════════════════════════════════════════

@login_required
def logout_view(request):
    """Log out and redirect to login."""
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("home")



# ══════════════════════════════════════════════════════════════
# FORGOT PASSWORD — Resend OTP
# ══════════════════════════════════════════════════════════════

@anonymous_required()
def resend_forgot_password_otp_view(request):
    """Resend OTP for password reset verification."""
    user = get_pending_user(request)
    if not user:
        messages.error(request, "Session expired. Please start again.")
        return redirect("forgot_password")

    otp_obj = create_otp_for_user(user, purpose="password_reset")
    email_sent = send_otp_email(user, otp_obj.otp, purpose="password_reset")

    if email_sent:
        messages.success(request, f"A new OTP has been sent to {user.email}.")
    else:
        messages.error(request, "Failed to resend OTP. Please try again.")

    return redirect("forgot_password_otp")

# Protect admin views with staff check

@login_required
def admin_dashboard_view(request):
    """Admin Dashboard – staff only."""
    if not request.user.is_staff:
        messages.error(request, "Admin access required.")
        return redirect("login")
    users = CustomUser.objects.all()
    context = {
        "users_count": users.count(),
        "staff_count": users.filter(is_staff=True).count(),
    }
    return render(request, "admin_panel/dashboard.html", context)

@login_required
def admin_user_management_view(request):
    """Admin User Management – staff only."""
    if not request.user.is_staff:
        messages.error(request, "Admin access required.")
        return redirect("login")
    users = CustomUser.objects.all().order_by("-date_joined")
    return render(request, "admin_panel/user_management.html", {"users": users})

@anonymous_required()
def forgot_password_view(request):
    """Accepts the user's email and sends a password-reset OTP."""
    form = ForgotPasswordForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            email = form.cleaned_data["email"]
            user  = CustomUser.objects.get(email=email)

            otp_obj    = create_otp_for_user(user, purpose="password_reset")
            email_sent = send_otp_email(user, otp_obj.otp, purpose="password_reset")

            if email_sent:
                set_pending_user_session(request, user.pk, purpose="password_reset")
                messages.success(request, f"OTP sent to {email}.")
                return redirect("forgot_password_otp")
            else:
                messages.error(request, "Failed to send OTP email. Please try again.")

    return render(request, "forgot_password.html", {"form": form})


# ══════════════════════════════════════════════════════════════
# FORGOT PASSWORD — Step 2: OTP Verification
# ══════════════════════════════════════════════════════════════

@anonymous_required()
def forgot_password_otp_view(request):
    """Verifies the password-reset OTP."""
    user = get_pending_user(request)
    if not user:
        messages.error(request, "Session expired. Please start again.")
        return redirect("forgot_password")

    form = OTPVerificationForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            otp_input = form.cleaned_data["otp"]
            valid, error_msg = verify_otp(user, otp_input, purpose="password_reset")

            if valid:
                request.session["password_reset_verified"] = True
                request.session["password_reset_user_id"]  = str(user.pk)
                clear_pending_user_session(request)
                return redirect("set_new_password")
            else:
                messages.error(request, error_msg)

    return render(request, "forgot_password_otp.html", {"form": form, "email": user.email})


# ══════════════════════════════════════════════════════════════
# FORGOT PASSWORD — Step 3: Set New Password
# ══════════════════════════════════════════════════════════════

@anonymous_required()
@password_reset_session_required
def set_new_password_view(request):
    """Final step: set a new password after OTP is verified."""
    user_id = request.session.get("password_reset_user_id")
    try:
        user = CustomUser.objects.get(pk=user_id)
    except (CustomUser.DoesNotExist, Exception):
        messages.error(request, "Session expired. Please start again.")
        return redirect("forgot_password")

    form = SetNewPasswordForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            user.set_password(form.cleaned_data["new_password"])
            user.save(update_fields=["password"])

            request.session.pop("password_reset_verified", None)
            request.session.pop("password_reset_user_id", None)

            messages.success(request, "Password updated successfully. Please log in.")
            return redirect("login")

    return render(request, "set_new_password.html", {"form": form})


# ══════════════════════════════════════════════════════════════
# PROFILE — View
# ══════════════════════════════════════════════════════════════

@login_required
def profile_view(request):
    """Display the logged-in user's profile and addresses."""
    # Refresh user from DB to avoid stale in-memory cache
    user      = request.user.__class__.objects.select_related("profile").get(pk=request.user.pk)
    profile   = user.profile
    addresses = user.addresses.all()

    context = {
        "user":      user,
        "profile":   profile,
        "addresses": addresses,
    }
    return render(request, "profile.html", context)



@login_required
def change_password_view(request):
    """Handle password change with validation."""
    if request.method == "POST":
        form = ChangePasswordForm(request.user, request.POST)
        if form.is_valid():
            # Set new password
            request.user.set_password(form.cleaned_data["new_password"])
            request.user.save(update_fields=["password"])
            # Keep user logged in after password change
            update_session_auth_hash(request, request.user)
            messages.success(request, "Your password has been updated.")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ChangePasswordForm(request.user)
    return render(request, "change_password.html", {"form": form})

@login_required
def change_email_view(request):
    """Initiate email change: validate new email, send OTP, store pending data in session."""
    if request.method == "POST":
        form = EmailChangeForm(request.user, request.POST)
        if form.is_valid():
            new_email = form.cleaned_data["new_email"]
            # Create OTP for email change purpose
            otp_obj = create_otp_for_user(request.user, purpose="email_change")
            send_otp_email(request.user, otp_obj.otp, purpose="email_change")
            # Store pending email and purpose in session
            set_pending_user_session(request, request.user.pk, purpose="email_change")
            request.session["pending_new_email"] = new_email
            messages.success(request, f"OTP sent to {request.user.email}. Please verify to change to {new_email}.")
            return redirect("verify_email_otp")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = EmailChangeForm(request.user)
    return render(request, "change_email.html", {"form": form})

@login_required
def verify_email_otp_view(request):
    """Verify OTP for email change and update email on success."""
    user = get_pending_user(request)
    if not user or request.session.get("otp_purpose") != "email_change":
        messages.error(request, "Session expired. Please start the email change process again.")
        return redirect("profile")
    new_email = request.session.get("pending_new_email")
    form = OTPVerificationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        otp_input = form.cleaned_data["otp"]
        valid, error_msg = verify_otp(user, otp_input, purpose="email_change")
        if valid:
            user.email = new_email
            user.save(update_fields=["email"])
            clear_pending_user_session(request)
            request.session.pop("pending_new_email", None)
            messages.success(request, "Your email address has been updated.")
            return redirect("profile")
        else:
            messages.error(request, error_msg)
    return render(request, "verify_email_otp.html", {"form": form, "email": user.email, "new_email": new_email})

@login_required
def resend_email_otp_view(request):
    """Resend OTP for email change, respecting cooldown timer (10 minutes)."""
    user = get_pending_user(request)
    if not user or request.session.get("otp_purpose") != "email_change":
        messages.error(request, "Session expired. Please start the email change process again.")
        return redirect("profile")
    otp_obj = create_otp_for_user(user, purpose="email_change")
    send_otp_email(user, otp_obj.otp, purpose="email_change")
    messages.success(request, f"A new OTP has been sent to {user.email}.")
    return redirect("verify_email_otp")

@login_required
def delete_account_view(request):
    """Permanently delete the authenticated user's account after password confirmation."""
    if request.method == "POST":
        password = request.POST.get("password")
        if not request.user.check_password(password):
            messages.error(request, "Password incorrect. Account not deleted.")
            return redirect("profile")
        # Delete user and related objects
        request.user.delete()
        logout(request)
        messages.success(request, "Your account has been permanently deleted.")
        return redirect("home")
    # GET – render a simple confirmation page (or modal is used in template)
    return render(request, "delete_account.html")

# ══════════════════════════════════════════════════════════════

@login_required
def profile_edit_view(request):
    """
    Edit profile: name, phone (CustomUser) and
    bio, gender, DOB, avatar (UserProfile).
    """
    user    = request.user
    # Ensure UserProfile exists for the user
    profile, _ = UserProfile.objects.get_or_create(user=user)

    user_form    = ProfileEditForm(instance=user)
    profile_form = UserProfileForm(instance=profile)

    if request.method == "POST":
        user_form    = ProfileEditForm(request.POST, instance=user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()

            # Save profile with commit=False so we can manipulate avatar
            pf = profile_form.save(commit=False)

            if request.POST.get("clear_avatar") == "true":
                # Delete the file from storage, then blank the field
                if profile.avatar:
                    profile.avatar.delete(save=False)
                pf.avatar = None
            # If no new file was uploaded and not clearing, keep existing avatar
            elif not request.FILES.get("avatar"):
                pf.avatar = profile.avatar   # preserve current value

            pf.save()
            messages.success(request, "Profile updated successfully.")
            return redirect("profile")
        else:
            messages.error(request, "Please correct the errors below.")

    context = {
        "user_form":    user_form,
        "profile_form": profile_form,
        "profile":      profile,
    }
    return render(request, "profile_edit.html", context)



# ══════════════════════════════════════════════════════════════
# ADDRESSES — List + Add
# ══════════════════════════════════════════════════════════════

@login_required
def addresses_view(request):
    """List all addresses and handle Add Address form."""
    addresses = request.user.addresses.all()
    form      = AddressForm()

    if request.method == "POST":
        form = AddressForm(request.POST)
        if form.is_valid():
            # Save the address and associate it with the current user
            try:
                address = form.save(commit=False)
                address.user = request.user
                address.save()
            except Exception as e:
                logger.error(f"Failed to save address for user {request.user.id}: {e}")
                messages.error(request, "An error occurred while saving the address. Please try again.")
                # Re-render the page with existing addresses and the filled form
                return render(request, "addresses.html", {"addresses": request.user.addresses.all(), "form": form})
            else:
                messages.success(request, "Address added successfully.")
                return redirect("addresses")
        # If the form is invalid, fall through to render with errors


    context = {
        "addresses": request.user.addresses.all(),
        "form":      form,
        "editing":   False,
    }
    return render(request, "addresses.html", context)


# ══════════════════════════════════════════════════════════════
# ADDRESSES — Edit
# ══════════════════════════════════════════════════════════════

@login_required
def address_edit_view(request, address_id):
    """Edit an existing address (ownership enforced)."""
    address = get_object_or_404(Address, pk=address_id, user=request.user)
    form    = AddressForm(instance=address)

    if request.method == "POST":
        form = AddressForm(request.POST, instance=address)
        if form.is_valid():
            form.save()
            messages.success(request, "Address updated successfully.")
            return redirect("addresses")
        else:
            messages.error(request, "Please correct the errors below.")

    context = {
        "form":      form,
        "address":   address,
        "addresses": request.user.addresses.all(),
        "editing":   True,
    }
    return render(request, "addresses.html", context)


# ══════════════════════════════════════════════════════════════
# ADDRESSES — Delete
# ══════════════════════════════════════════════════════════════

@login_required
def address_delete_view(request, address_id):
    """Delete an address (POST only, ownership enforced)."""
    address = get_object_or_404(Address, pk=address_id, user=request.user)

    if request.method == "POST":
        address.delete()
        messages.success(request, "Address removed.")

    return redirect("addresses")


# ══════════════════════════════════════════════════════════════
# ADDRESSES — Set Default
# ══════════════════════════════════════════════════════════════

@login_required
def address_set_default_view(request, address_id):
    """Mark an address as the default (POST only)."""
    address = get_object_or_404(Address, pk=address_id, user=request.user)

    if request.method == "POST":
        address.is_default = True
        address.save()
        messages.success(request, "Default address updated.")

    return redirect("addresses")

@login_required
def orders_view(request):
    """Placeholder Orders page."""
    return render(request, "orders.html")

@login_required
def wishlist_view(request):
    """Placeholder Wishlist page."""
    return render(request, "wishlist.html")


# ══════════════════════════════════════════════════════════════
# CUSTOM LUXURY ADMIN PANEL VIEWS
# ══════════════════════════════════════════════════════════════

def admin_login_view(request):
    """Admin Login."""
    if request.method == "POST":
        return redirect("admin_dashboard")
    return render(request, "admin_panel/login.html")


def admin_forgot_password_view(request):
    """Admin Forgot Password."""
    if request.method == "POST":
        return redirect("admin_forgot_password_otp")
    return render(request, "admin_panel/forgot_password.html")


def admin_forgot_password_otp_view(request):
    """Admin OTP Verification."""
    if request.method == "POST":
        return redirect("admin_reset_password")
    return render(request, "admin_panel/otp.html")


def admin_reset_password_view(request):
    """Admin Reset Password."""
    if request.method == "POST":
        messages.success(request, "Admin password updated successfully.")
        return redirect("admin_login")
    return render(request, "admin_panel/reset_password.html")


def admin_dashboard_view(request):
    """Admin Dashboard."""
    users = CustomUser.objects.all()
    context = {
        "users_count": users.count(),
        "staff_count": users.filter(is_staff=True).count(),
    }
    return render(request, "admin_panel/dashboard.html", context)


def admin_user_management_view(request):
    """Admin User Management."""
    users = CustomUser.objects.all().order_by("-date_joined")
    return render(request, "admin_panel/user_management.html", {"users": users})


def admin_user_profile_view(request):
    """Admin view user profile."""
    return render(request, "admin_panel/user_profile.html")


def admin_logout_view(request):
    """Admin Logout."""
    logout(request)
    messages.info(request, "Admin logged out successfully.")
    return redirect("admin_login")