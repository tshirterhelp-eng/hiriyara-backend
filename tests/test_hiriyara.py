"""Backend tests for Hiriyara Mane API (public + auth + admin)."""
import os
import time
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://poster-info-hub.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@hiriyaramane.com"
ADMIN_PASSWORD = "HiriyaraMane@2026"


@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def admin_token(session):
    r = session.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data
    assert data["user"]["email"] == ADMIN_EMAIL
    assert data["user"]["role"] == "admin"
    # Cookie should be set
    assert "access_token" in r.cookies, "httpOnly access_token cookie not set"
    return data["access_token"]


@pytest.fixture(scope="session")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


# ---------- Public ----------
class TestPublic:
    def test_root(self, session):
        r = session.get(f"{API}/")
        assert r.status_code == 200
        body = r.json()
        assert body.get("status") == "ok"
        assert "Hiriyara" in body.get("message", "")

    def test_healthz(self, session):
        r = session.get(f"{API}/healthz")
        assert r.status_code == 200
        assert r.json() == {"ok": True}


class TestEnquiryCreate:
    def test_create_valid(self, session):
        payload = {
            "name": "TEST_John Doe",
            "phone": "+919449064567",
            "email": "test_john@example.com",
            "message": "Need details for my mother's stay.",
            "relation": "Son",
        }
        r = session.post(f"{API}/enquiries", json=payload)
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["id"]
        assert data["status"] == "new"
        assert data["name"] == payload["name"]
        assert data["phone"] == payload["phone"]
        assert "created_at" in data
        # ISO string check
        assert "T" in data["created_at"]
        pytest.created_id = data["id"]

    def test_create_minimal_no_email(self, session):
        r = session.post(f"{API}/enquiries", json={
            "name": "TEST_NoEmail",
            "phone": "9999999999",
            "message": "Hello there please contact me",
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["email"] is None
        assert body["relation"] is None

    def test_create_missing_required(self, session):
        r = session.post(f"{API}/enquiries", json={"name": "X"})
        assert r.status_code == 422

    def test_create_short_name(self, session):
        r = session.post(f"{API}/enquiries", json={
            "name": "A", "phone": "9999999999", "message": "Hello there"
        })
        assert r.status_code == 422

    def test_create_short_message(self, session):
        r = session.post(f"{API}/enquiries", json={
            "name": "Ab", "phone": "9999999999", "message": "hi"
        })
        assert r.status_code == 422

    def test_create_short_phone(self, session):
        r = session.post(f"{API}/enquiries", json={
            "name": "Ab", "phone": "123", "message": "Hello there"
        })
        assert r.status_code == 422


# ---------- Auth ----------
class TestAuth:
    def test_login_success(self, session):
        r = session.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200
        d = r.json()
        assert d["access_token"]
        assert d["user"]["email"] == ADMIN_EMAIL
        assert d["user"]["role"] == "admin"
        # password_hash never leaks
        assert "password_hash" not in d["user"]

    def test_login_wrong_password(self, session):
        r = session.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "wrongPW123!"})
        assert r.status_code == 401
        assert "Invalid email or password" in r.json().get("detail", "")

    def test_login_unknown_email(self, session):
        r = session.post(f"{API}/auth/login", json={"email": "nope@hiriyaramane.com", "password": "whatever"})
        assert r.status_code == 401

    def test_me_with_bearer(self, session, auth_headers):
        r = session.get(f"{API}/auth/me", headers=auth_headers)
        assert r.status_code == 200
        d = r.json()
        assert d["email"] == ADMIN_EMAIL
        assert d["role"] == "admin"

    def test_me_without_token(self):
        s = requests.Session()
        r = s.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_me_invalid_token(self):
        s = requests.Session()
        r = s.get(f"{API}/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_logout(self, session):
        # Login fresh to receive cookie
        s = requests.Session()
        lr = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert lr.status_code == 200
        assert "access_token" in s.cookies
        out = s.post(f"{API}/auth/logout")
        assert out.status_code == 200
        assert out.json().get("ok") is True


# ---------- Admin ----------
class TestAdminEnquiries:
    def test_list_requires_auth(self, session):
        s = requests.Session()
        r = s.get(f"{API}/admin/enquiries")
        assert r.status_code == 401

    def test_list_with_auth_sorted_desc(self, session, auth_headers):
        # Create two enquiries with a small gap
        a = session.post(f"{API}/enquiries", json={
            "name": "TEST_OrderA", "phone": "9000000001", "message": "first one for sort test"
        }).json()
        time.sleep(1.1)
        b = session.post(f"{API}/enquiries", json={
            "name": "TEST_OrderB", "phone": "9000000002", "message": "second one for sort test"
        }).json()

        r = session.get(f"{API}/admin/enquiries", headers=auth_headers)
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list)
        assert len(items) >= 2
        # Verify sorted by created_at desc
        created_ats = [it["created_at"] for it in items]
        assert created_ats == sorted(created_ats, reverse=True)
        ids = [it["id"] for it in items]
        # b should appear before a
        assert ids.index(b["id"]) < ids.index(a["id"])

    def test_patch_status_valid(self, session, auth_headers):
        eid = getattr(pytest, "created_id", None)
        if not eid:
            new = session.post(f"{API}/enquiries", json={
                "name": "TEST_Patch", "phone": "9000000003", "message": "patch test message"
            }).json()
            eid = new["id"]
        r = session.patch(f"{API}/admin/enquiries/{eid}",
                          json={"status": "contacted"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["status"] == "contacted"

        # verify persistence
        lst = session.get(f"{API}/admin/enquiries", headers=auth_headers).json()
        for e in lst:
            if e["id"] == eid:
                assert e["status"] == "contacted"
                break

    def test_patch_status_invalid(self, session, auth_headers):
        eid = getattr(pytest, "created_id", None)
        if not eid:
            new = session.post(f"{API}/enquiries", json={
                "name": "TEST_PatchInv", "phone": "9000000004", "message": "bad status patch"
            }).json()
            eid = new["id"]
        r = session.patch(f"{API}/admin/enquiries/{eid}",
                          json={"status": "bogus"}, headers=auth_headers)
        assert r.status_code == 400

    def test_patch_not_found(self, session, auth_headers):
        r = session.patch(f"{API}/admin/enquiries/non-existent-uuid",
                          json={"status": "new"}, headers=auth_headers)
        assert r.status_code == 404

    def test_delete_and_verify(self, session, auth_headers):
        new = session.post(f"{API}/enquiries", json={
            "name": "TEST_Delete", "phone": "9000000099", "message": "to be deleted soon"
        }).json()
        eid = new["id"]
        d = session.delete(f"{API}/admin/enquiries/{eid}", headers=auth_headers)
        assert d.status_code == 200
        assert d.json().get("ok") is True
        # GET list and ensure id not present
        lst = session.get(f"{API}/admin/enquiries", headers=auth_headers).json()
        assert all(e["id"] != eid for e in lst)

    def test_delete_not_found(self, session, auth_headers):
        r = session.delete(f"{API}/admin/enquiries/non-existent-uuid", headers=auth_headers)
        assert r.status_code == 404

    def test_stats_requires_auth(self):
        s = requests.Session()
        r = s.get(f"{API}/admin/stats")
        assert r.status_code == 401

    def test_stats_shape(self, session, auth_headers):
        r = session.get(f"{API}/admin/stats", headers=auth_headers)
        assert r.status_code == 200
        d = r.json()
        for k in ("total", "new", "contacted", "closed"):
            assert k in d
            assert isinstance(d[k], int)
        assert d["total"] >= d["new"] + d["contacted"] + d["closed"] - 0


# ---------- Cleanup ----------
@pytest.fixture(scope="session", autouse=True)
def cleanup(session):
    yield
    # Best-effort cleanup of TEST_ enquiries
    try:
        login = session.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        token = login.json().get("access_token")
        if not token:
            return
        headers = {"Authorization": f"Bearer {token}"}
        lst = session.get(f"{API}/admin/enquiries", headers=headers).json()
        for e in lst:
            if isinstance(e.get("name"), str) and e["name"].startswith("TEST_"):
                session.delete(f"{API}/admin/enquiries/{e['id']}", headers=headers)
    except Exception:
        pass
