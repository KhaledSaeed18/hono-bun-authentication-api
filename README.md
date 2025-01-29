# Hono/Bun Authentication API 🔐

[![Bun](https://img.shields.io/badge/Runtime-Bun-%23000000.svg?style=flat&logo=bun)](https://bun.sh) [![Hono](https://img.shields.io/badge/Framework-Hono-%23000000.svg?style=flat)](https://hono.dev) [![Prisma](https://img.shields.io/badge/ORM-Prisma-%232D3748.svg?style=flat&logo=prisma)](https://prisma.io) [![TypeScript](https://img.shields.io/badge/Language-TypeScript-%23007ACC.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)

A secure, modern authentication API built with Hono, Bun, and Prisma. Features JWT authentication, rate limiting, and enterprise-grade security headers.

## ✨ Features

- 🔒 JWT-based authentication with 24-hour expiration  
- ⚡ Bun runtime for exceptional performance  
- 🛡️ Advanced security headers (CSP, HSTS, XSS Protection)  
- 🚦 Rate limiting (5 requests/15 minutes per IP)  
- 📦 Prisma ORM with MongoDB integration  
- ✅ Zod schema validation

## 🚀 Getting Started

### Prerequisites

- Bun v1.2.1

### Installation

```bash
# Clone repository
git clone https://github.com/KhaledSaeed18/hono-bun-authentication-api.git
cd hono-bun-authentication-api

# Install dependencies
bun install

# Set up Prisma
bunx prisma generate
bunx prisma db push
```

### Environment Setup

Create `.env` file:

```env
DATABASE_URL=
JWT_SECRET=
PORT=
```

## 📚 API Documentation

### Endpoints

| Method | Endpoint    | Description                | Rate Limited |
|--------|-------------|----------------------------|--------------|
| POST   | /api/signup | Register new user          | ✅           |
| POST   | /api/signin | Authenticate user          | ✅           |
| GET    | /api/me     | Get current user profile   | ✅           |

### Request Examples

**Sign Up:**

```bash
curl -X POST http://localhost:3000/api/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

**Sign In:**

```bash
curl -X POST http://localhost:3000/api/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

**Get Profile:**

```bash
curl -X GET http://localhost:3000/api/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔧 Configuration

### Environment Variables

| Variable        | Required | Description                     | Default |
|-----------------|----------|---------------------------------|---------|
| DATABASE_URL    | Yes      | MongoDB connection string       | -       |
| JWT_SECRET      | Yes      | 256-bit JWT signing secret      | -       |
| PORT            | No       | Application port                | 3000    |

## 🛡️ Security Features

- **Password Requirements:**  
  - Minimum 8 characters  
  - At least 1 uppercase, 1 lowercase, 1 number, 1 special character  
- **Security Headers:**  
  - Strict-Transport-Security  
  - X-Content-Type-Options  
  - X-Frame-Options  
  - X-XSS-Protection  
- **IP-based Rate Limiting**  
- **JWT Best Practices:**  
  - HS256 algorithm  
  - Short-lived tokens (24h)  
  - Secure cookie storage ready
