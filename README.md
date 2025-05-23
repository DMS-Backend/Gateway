# Python API Gateway

This is a Flask-based API Gateway that routes requests to multiple backend microservices (e.g., Auth Service, Hello World Services), handling authentication, authorization (via JWT), and role-based access control.

---

## 🚀 Features

- Reverse proxy for microservices (Auth, Hello1, Hello2, etc.)
- JWT-based authentication and role verification
- Environment-variable-based configuration
- Secure forwarding of the `Authorization` Bearer token
- Centralized logging for easier debugging

---

## 🛠️ Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/python-api-gateway.git
cd python-api-gateway
````

### 2. Create `.env` File

```bash
cp .env.example .env
```

Fill in the environment variables in the `.env` file:

```env
AUTH_SERVICE_URL=http://localhost:8081
HELLO_WORLD_SERVICE_1_URL=http://localhost:8080
HELLO_WORLD_SERVICE_2_URL=http://localhost:8082
JWT_SECRET=yourVerySecretKeyAtLeast32CharsLong
PORT=5000
```

> **Warning:** Never commit `.env` to version control (see `.gitignore`).

---

## 🧪 Run Locally

### Using Python

```bash
pip install -r requirements.txt
python gateway.py
```

Or with:

```bash
flask run
```

---

## 🔐 Authorization

Routes requiring authentication should include the `Authorization` header:

```
Authorization: Bearer <your_jwt_token>
```

The gateway checks:

* Token validity
* User roles (if required by the route)

---

## 🧪 Example Request

```bash
curl -X GET http://localhost:5000/api/hello-1 \
  -H "Authorization: Bearer <your_valid_jwt>"
```

---

## 📁 Folder Structure

```
├── gateway.py
├── .env
├── .gitignore
├── README.md
└── requirements.txt
```

---

## ✅ Routes Configuration

Routes are defined in the `ROUTES` dictionary inside `gateway.py`, and support:

* HTTP method matching
* Optional role checks (`'roles': ['ROLE_ADMIN']`)
* JWT-based authentication enforcement (`'authenticated': True`)