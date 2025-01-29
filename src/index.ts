import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { rateLimiter } from 'hono-rate-limiter'
import { PrismaClient } from '@prisma/client'
import { z } from 'zod'
import { jwt, sign } from 'hono/jwt';

const app = new Hono()
const prisma = new PrismaClient()

const jwtSecret = process.env.JWT_SECRET

app.use('*', cors())

app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

const authLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5, // 5 attempts
  keyGenerator: (c) => {
    const ip = c.req.header('x-forwarded-for') || 'unknown';
    return ip;
  }
})

const authMiddleware = jwt({
  secret: process.env.JWT_SECRET!
})

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

const signinSchema = z.object({
  email: z.string()
    .trim()
    .toLowerCase()
    .email(),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
})

app.post('/api/signup', authLimiter, async (c) => {
  const body = await c.req.json()
  const parsed = signupSchema.safeParse(body)

  if (!parsed.success) {
    const errorMessages = parsed.error.issues.map(issue => issue.message)
    if (errorMessages.length === 1) {
      return c.json({ message: errorMessages[0] }, 400)
    }
    return c.json({ errors: errorMessages }, 400)
  }

  const { username, email, password } = parsed.data

  try {
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email,
      }
    })

    if (existingUser) {
      return c.json({
        statusCode: 409,
        message: 'User already exists',
      }, 409)
    }

    const hashedPassword = await Bun.password.hash(password)

    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      }
    })

    return c.json({
      statusCode: 201,
      message: 'User created successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
      }
    }, 201)
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Internal server error'
    return c.json({ error }, 500)
  }
})

app.post('/api/signin', authLimiter, async (c) => {
  const body = await c.req.json()
  const parsed = signinSchema.safeParse(body)

  if (!parsed.success) {
    const errorMessages = parsed.error.issues.map(issue => issue.message)
    if (errorMessages.length === 1) {
      return c.json({ message: errorMessages[0] }, 400)
    }
    return c.json({ errors: errorMessages }, 400)
  }

  const { email, password } = body

  try {
    const user = await prisma.user.findUnique({
      where: {
        email: email,
      }
    })

    if (!user) {
      return c.json({
        statusCode: 404,
        message: 'User not found',
      }, 404)
    }

    const passwordMatch = await Bun.password.verify(password, user.password)

    if (!passwordMatch) {
      return c.json({
        statusCode: 401,
        message: 'Invalid credentials',
      }, 401)
    }

    const token = await sign({
      userId: user.id,
      iat: Math.floor(Date.now() / 1000), // issued at
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // expires in 24 hours
    }, jwtSecret!)

    return c.json({
      statusCode: 200,
      message: 'Signin successful',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        token
      }
    }, 200)
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Internal server error'
    return c.json({ error }, 500)
  }
})

app.get('/api/me', authLimiter, authMiddleware, async (c) => {
  try {
    const userId = c.get('jwtPayload').userId

    if (!userId) {
      return c.json({
        statusCode: 401,
        message: 'Unauthorized'
      }, 401)
    }

    const user = await prisma.user.findUnique({
      where: {
        id: userId
      },
      select: {
        id: true,
        username: true,
        email: true,
        createdAt: true
      }
    })

    if (!user) {
      return c.json({
        statusCode: 404,
        message: 'User not found',
      }, 404)
    }

    const formattedDate = new Date(user.createdAt).toLocaleString()

    return c.json({
      statusCode: 200,
      message: 'Data fetched successfully',
      data: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: formattedDate
      }
    }, 200)
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Internal server error'
    return c.json({ error }, 500)
  }
})


export default {
  port: process.env.PORT,
  fetch: app.fetch,
}
