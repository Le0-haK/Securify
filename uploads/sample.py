from django.db.models import F, Value, Func
from django.db.models.expressions import RawSQL
from django.contrib.auth.models import User

def my_view(request):
    # Untrusted input from the request
    user_input = request.GET.get('username')

    # Using `RawSQL` to inject raw SQL into an annotation
    users = User.objects.annotate(
        is_admin=RawSQL("SELECT is_staff FROM auth_user WHERE username = %s", [user_input])
    )

    return render(request, 'template.html', {'users': users})

def my_view_1():
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    query = "SELECT * FROM users"
    query(query)
