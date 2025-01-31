import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { rateLimiter } from 'hono-rate-limiter'
import { PrismaClient } from '@prisma/client'
import { z } from 'zod'
import { jwt, sign } from 'hono/jwt';

const app = new Hono()
const prisma = new PrismaClient()

const jwtSecret = process.env.JWT_SECRET

// Enable CORS for all routes
app.use('*', cors())

// Security middleware to add headers for security best practices
app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'DENY')
  c.header('X-XSS-Protection', '1; mode=block')
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
})

// Rate limiter for authentication endpoints to prevent brute-force attacks
const authLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5, // Allow up to 5 requests per window per IP
  keyGenerator: (c) => c.req.raw.headers.get('x-forwarded-for') || c.req.raw.headers.get('cf-connecting-ip') || c.req.raw.headers.get('x-real-ip') || c.req.raw.headers.get('remote-addr') || 'unknown'
})

// JWT authentication middleware
const authMiddleware = jwt({
  secret: process.env.JWT_SECRET!
})

// Validation schema for user signup using Zod
const signupSchema = z.object({
  username: z.string()
    .trim()
    .min(2, "Username must be at least 2 characters")
    .max(20, "Username must be at most 20 characters"),
  email: z.string()
    .trim()
    .toLowerCase()
    .email(),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(/[#?!@$%^&*-]/, "Password must contain at least one special character (#?!@$%^&*-)")
})

// Validation schema for user signin
const signinSchema = z.object({
  email: z.string()
    .trim()
    .toLowerCase()
    .email(),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
})

// User signup endpoint
app.post('/api/signup', authLimiter, async (c) => {
  const body = await c.req.json()
  const parsed = signupSchema.safeParse(body)

  if (!parsed.success) {
    const errorMessages = parsed.error.issues.map(issue => issue.message)
    return c.json({ errors: errorMessages }, 400)
  }

  const { username, email, password } = parsed.data

  try {
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    })

    if (existingUser) {
      return c.json({ statusCode: 409, message: 'User already exists' }, 409)
    }

    // Hash password before storing it
    const hashedPassword = await Bun.password.hash(password)

    // Create new user
    const user = await prisma.user.create({
      data: { username, email, password: hashedPassword }
    })

    return c.json({ statusCode: 201, message: 'User created successfully', data: { id: user.id, username, email } }, 201)
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Internal server error' }, 500)
  }
})

// User signin endpoint
app.post('/api/signin', authLimiter, async (c) => {
  const body = await c.req.json()
  const parsed = signinSchema.safeParse(body)

  if (!parsed.success) {
    const errorMessages = parsed.error.issues.map(issue => issue.message)
    return c.json({ errors: errorMessages }, 400)
  }

  const { email, password } = body

  try {
    // Find user by email
    const user = await prisma.user.findUnique({ where: { email } })

    if (!user) {
      return c.json({ statusCode: 404, message: 'User not found' }, 404)
    }

    // Verify password
    const passwordMatch = await Bun.password.verify(password, user.password)

    if (!passwordMatch) {
      return c.json({ statusCode: 401, message: 'Invalid credentials' }, 401)
    }

    // Generate JWT token
    const token = await sign({
      userId: user.id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 24 hours expiration
    }, jwtSecret!)

    return c.json({ statusCode: 200, message: 'Signin successful', data: { id: user.id, username: user.username, email, token } }, 200)
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Internal server error' }, 500)
  }
})

// Get authenticated user data
app.get('/api/me', authLimiter, authMiddleware, async (c) => {
  try {
    const userId = c.get('jwtPayload').userId

    if (!userId) {
      return c.json({ statusCode: 401, message: 'Unauthorized' }, 401)
    }

    // Fetch user details excluding password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true, email: true, createdAt: true }
    })

    if (!user) {
      return c.json({ statusCode: 404, message: 'User not found' }, 404)
    }

    const formattedDate = new Date(user.createdAt).toLocaleString()

    return c.json({ statusCode: 200, message: 'Data fetched successfully', data: { id: user.id, username: user.username, email: user.email, createdAt: formattedDate } }, 200)
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : 'Internal server error' }, 500)
  }
})

export default {
  port: process.env.PORT || 3000,
  fetch: app.fetch,
}
