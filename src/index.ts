import { Context, Env, Hono } from 'hono'
import { cors } from 'hono/cors'
import { Promisify, rateLimiter } from 'hono-rate-limiter'
import { PrismaClient } from '@prisma/client'
import { z } from 'zod'

const app = new Hono()
const prisma = new PrismaClient()

app.use('*', cors())
app.use('*',
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    keyGenerator: (c) => c.req.header('x-forwarded-for') || 'unknown'
  })
)

const signupSchema = z.object({
  username: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
})

app.post('/api/signup', async (c) => {

  const body = await c.req.json()
  const parsed = signupSchema.safeParse(body)

  if (!parsed.success) {
    return c.json({ error: parsed.error }, 400)
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

    const user = await prisma.user.create({
      data: {
        username,
        email,
        password,
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
    console.error(error)
    return c.json({ error }, 500)
  }

})

export default app
