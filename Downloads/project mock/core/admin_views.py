from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.messages import get_messages
from .models import CustomUser

def is_admin(user):
    return user.is_authenticated and user.is_superuser

def admin_login_view(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('admin_dashboard')
        
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        
        if user is not None and user.is_superuser:
            login(request, user)
            messages.success(request, "Welcome to the Luxelle Admin Panel.")
            return redirect('admin_dashboard')
        else:
            messages.error(request, "Invalid credentials or you do not have admin access.")
            
    return render(request, 'admin_panel/login.html')

@user_passes_test(is_admin, login_url='admin_login')
def admin_dashboard_view(request):
    context = {
        'total_users': CustomUser.objects.filter(is_superuser=False).count(),
        'recent_users': CustomUser.objects.filter(is_superuser=False).order_by('-date_joined')[:5]
    }
    return render(request, 'admin_panel/dashboard.html', context)

@user_passes_test(is_admin, login_url='admin_login')
def admin_user_management_view(request):
    from django.utils import timezone
    from datetime import timedelta

    # Filter out stale login failure messages if an authenticated admin reaches this page
    storage = list(get_messages(request))
    for message in storage:
        if request.user.is_authenticated and request.user.is_superuser and str(message) == "Invalid credentials or you do not have admin access.":
            continue
        messages.add_message(request, message.level, message.message, extra_tags=message.extra_tags)
    
    users = CustomUser.objects.filter(is_superuser=False).order_by('-date_joined')
    active_count = users.filter(is_active=True).count()
    blocked_count = users.filter(is_active=False).count()
    
    # Count users joined this month
    today = timezone.now()
    first_day_of_month = today.replace(day=1)
    this_month_count = users.filter(date_joined__gte=first_day_of_month).count()
    
    context = {
        'users': users,
        'active_count': active_count,
        'blocked_count': blocked_count,
        'this_month_count': this_month_count,
    }
    return render(request, 'admin_panel/user_management.html', context)

@user_passes_test(is_admin, login_url='admin_login')
def admin_user_profile_view(request):
    return render(request, 'admin_panel/user_profile.html')

@user_passes_test(is_admin, login_url='admin_login')
def admin_toggle_user_status_view(request, user_id):
    """Block or unblock a user (toggle is_active status)"""
    try:
        user = CustomUser.objects.get(id=user_id, is_superuser=False)
        user.is_active = not user.is_active
        user.save(update_fields=['is_active'])
        
        action = "unblocked" if user.is_active else "blocked"
        messages.success(request, f"User {user.get_full_name()} has been {action}.", extra_tags='success')
    except CustomUser.DoesNotExist:
        messages.error(request, "User not found.", extra_tags='error')
    
    return redirect('admin_users')

@user_passes_test(is_admin, login_url='admin_login')
def admin_delete_user_view(request, user_id):
    """Delete a user account"""
    try:
        user = CustomUser.objects.get(id=user_id, is_superuser=False)
        user_name = user.get_full_name()
        user.delete()
        messages.success(request, f"User {user_name} has been permanently deleted.", extra_tags='success')
    except CustomUser.DoesNotExist:
        messages.error(request, "User not found.", extra_tags='error')
    
    return redirect('admin_users')

def admin_logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out of the Admin Panel.")
    return redirect('admin_login')

from .utils import create_otp_for_user, send_otp_email, set_pending_user_session

def admin_forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        try:
            user = CustomUser.objects.get(email=email, is_superuser=True)
            # Create OTP and send email
            otp_obj = create_otp_for_user(user, purpose="password_reset")
            send_otp_email(user, otp_obj.otp, purpose="password_reset")
            
            # Store in session
            set_pending_user_session(request, user.id, "password_reset")
            
            messages.success(request, f"An OTP has been sent to {user.email}")
            return redirect('admin_forgot_password_otp')
            
        except CustomUser.DoesNotExist:
            # Show same message for security reasons
            messages.success(request, "If an admin account with that email exists, an OTP has been sent.")
            return redirect('admin_forgot_password_otp')

    return render(request, 'admin_panel/forgot_password.html')

from .utils import verify_otp, get_pending_user, clear_pending_user_session
from .forms import SetNewPasswordForm

def admin_forgot_password_otp_view(request):
    user = get_pending_user(request)
    if not user or request.session.get("otp_purpose") != "password_reset":
        messages.error(request, "Session expired. Please request a new OTP.")
        return redirect('admin_forgot_password')

    if request.method == "POST":
        otp_input = request.POST.get("otp", "").strip()
        is_valid, msg = verify_otp(user, otp_input, "password_reset")
        if is_valid:
            # Mark OTP as verified for the next step
            request.session["password_reset_verified"] = True
            request.session["password_reset_user_id"] = str(user.id)
            clear_pending_user_session(request)
            messages.success(request, "OTP verified. Please enter your new password.")
            return redirect('admin_reset_password')
        else:
            messages.error(request, msg)

    return render(request, 'admin_panel/otp.html', {"email": user.email})

def admin_reset_password_view(request):
    # Verify they passed the OTP step
    if not request.session.get("password_reset_verified"):
        messages.error(request, "Please verify OTP first.")
        return redirect('admin_forgot_password')

    user_id = request.session.get("password_reset_user_id")
    try:
        user = CustomUser.objects.get(pk=user_id, is_superuser=True)
    except CustomUser.DoesNotExist:
        messages.error(request, "Session expired. Please start again.")
        return redirect('admin_forgot_password')

    form = SetNewPasswordForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            user.set_password(form.cleaned_data["new_password"])
            user.save(update_fields=["password"])

            request.session.pop("password_reset_verified", None)
            request.session.pop("password_reset_user_id", None)

            messages.success(request, "Password updated successfully. Please log in.")
            return redirect('admin_login')

    return render(request, 'admin_panel/reset_password.html', {"form": form})
