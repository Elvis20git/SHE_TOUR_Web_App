def navbar_context(request):
    context = {
        'user_full_name': request.user.get_full_name() if request.user.is_authenticated else '',
        'user_email': request.user.email if request.user.is_authenticated else '',
        # Add any other navbar-related context you need
        'unread_notifications_count': get_unread_notifications_count(request.user) if request.user.is_authenticated else 0,
    }
    return context

# Helper function to get notifications count
def get_unread_notifications_count(user):
    # Replace this with your actual notification logic
    try:
        return user.notifications.filter(read=False).count()
    except:
        return 0