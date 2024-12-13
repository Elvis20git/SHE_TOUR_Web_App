from locust import HttpUser, task, between
import random
import string
import json


class DjangoLoadTest(HttpUser):
    wait_time = between(1, 3)  # Reduced wait time for more realistic testing
    token = None
    session_cookie = None

    def get_csrf_and_session(self, url):
        """Get both CSRF token and session cookie"""
        response = self.client.get(url)
        token = None
        if "csrftoken" in response.cookies:
            token = response.cookies["csrftoken"]
        if "sessionid" in response.cookies:
            self.session_cookie = response.cookies["sessionid"]
        return token

    def generate_random_user(self):
        """Generate random user data"""
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        first_names = ["John", "Jane", "Mike", "Sarah", "David", "Emma", "Alex"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"]
        departments = ["IT", "HR", "Finance", "Marketing", "Operations", "Sales"]
        roles = ["user", "manager", "administrator"]

        password = ''.join(
            random.choice(string.ascii_letters + string.digits + string.punctuation)
            for _ in range(12)
        )

        return {
            "first_name": random.choice(first_names),
            "last_name": random.choice(last_names),
            "username": f"testuser_{random_string}",
            "email": f"test_{random_string}@example.com",
            "department": random.choice(departments),
            "role": random.choice(roles),
            "password1": password,
            "password2": password,
            "account_activation": True,
            "email_notifications": True,
            "reminder_frequency": random.randint(1, 30),
            "is_HOD": False
        }

    def register_and_login(self):
        """Combined registration and login process"""
        # Register
        self.token = self.get_csrf_and_session("/register/")

        headers = {
            "X-CSRFToken": self.token,
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"csrftoken={self.token}; sessionid={self.session_cookie}"
        }

        user_data = self.generate_random_user()
        self.current_user = user_data

        register_response = self.client.post(
            "/register/",
            data=user_data,
            headers=headers,
            catch_response=True
        )

        if register_response.status_code not in [200, 302]:
            return False

        # Login
        self.token = self.get_csrf_and_session("/")

        login_data = {
            "username": user_data["username"],
            "password": user_data["password1"],
            "remember_me": True
        }

        headers = {
            "X-CSRFToken": self.token,
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"csrftoken={self.token}; sessionid={self.session_cookie}"
        }

        with self.client.post(
                "/",
                data=login_data,
                headers=headers,
                catch_response=True
        ) as response:
            if response.status_code in [200, 302]:
                try:
                    json_response = response.json()
                    return json_response.get('success', False)
                except:
                    return response.status_code in [200, 302]
            return False

    def on_start(self):
        """Initialize test session"""
        self.is_logged_in = self.register_and_login()

    @task(3)
    def view_dashboard(self):
        """Test dashboard access with session validation"""
        if not self.is_logged_in:
            self.register_and_login()

        headers = {
            "Cookie": f"csrftoken={self.token}; sessionid={self.session_cookie}"
        }

        with self.client.get("/analytics/", headers=headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 302:
                # If redirected to login, try to re-login
                self.is_logged_in = self.register_and_login()
                response.success()
            else:
                response.failure(f"Dashboard failed with status {response.status_code}")

    @task(1)
    def test_invalid_login(self):
        """Test invalid login attempts"""
        self.token = self.get_csrf_and_session("/")

        headers = {
            "X-CSRFToken": self.token,
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"csrftoken={self.token}; sessionid={self.session_cookie}"
        }

        invalid_data = {
            "username": f"nonexistent_user_{random.randint(1000, 9999)}",
            "password": "wrong_password",
            "remember_me": False
        }

        with self.client.post(
                "/",
                data=invalid_data,
                headers=headers,
                catch_response=True
        ) as response:
            if response.status_code in [400, 401, 403]:  # Added 403 as valid failure
                response.success()
            else:
                response.failure(f"Expected error status, got {response.status_code}")

    def on_stop(self):
        """Clean logout"""
        if self.is_logged_in:
            headers = {
                "Cookie": f"csrftoken={self.token}; sessionid={self.session_cookie}"
            }
            self.client.get("/logout/", headers=headers, catch_response=True)

# Run with: locust --host=http://localhost:8000 --users 100 --spawn-rate 5