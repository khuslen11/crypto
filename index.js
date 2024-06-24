const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const jwt = require('jsonwebtoken')
const jwtSecret = process.env.JWT_SECRET
const argon2 = require('argon2')
const express = require('express')
const axios = require('axios')
const { z } = require('zod')
const app = express()
const port = 3000
app.use(express.json());

const signupSchema = z.object({
  name: z.string().min(1, 'name is required'),
  email: z.string().email('invalid email'),
  password: z.string().min(8, 'password required')
})

const loginSchema = z.object({
  email: z.string().email('invalid emial'),
  password: z.string().min(8, 'password required')
})

const apiCryptoSchema = z.object({
  api_key_val: z.string().min(1, 'api key required')
})

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = signupSchema.parse(req.body)
    const user = await prisma.api_user.findUnique({
      where: { email }
    })
    if (user) {
      return res.status(400).json({ error: 'email already exist' })
    }
    const hashedPassword = await argon2.hash(password)
    const { userS, apiKey, apiPlan } = await prisma.$transaction(async (prisma) => {
      const userS = await prisma.api_user.create({
        data: { name, email, password: hashedPassword }
      })

      const apiKey = await prisma.api_key.create({
        data: { owner_id: userS.user_id }
      })

      const apiPlan = await prisma.api_plan.create({
        data: { plan_key_id: apiKey.api_key_id }
      })

      return { userS, apiKey, apiPlan }
    })
    const tokenPayload = {
      name: userS.name,
      email: userS.email,
      user_id: userS.user_id,
      api_key_val: apiKey.api_key_val,
      plan_name: apiPlan.plan_name,
      plan_limit: apiPlan.plan_limit
    };
    const token = jwt.sign( tokenPayload , jwtSecret, { expiresIn: '1h' });

    res.status(200).json({ token, userS, apiKey })
  }
  catch (err) {
    if (err instanceof z.ZodError) {
      const errorMessages = err.errors.map(e => e.message).join(', ')
      return res.status(400).json({ error: errorMessages })
    }
    console.error('Internal Server Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body)
    const user = await prisma.api_user.findUnique({
      where: {
        email
      },
      include: {
        api_key: {
          include: {
            api_plan: true
          }
        }
      }
    })
    if (!user) {
      return res.status(401).json({ error: 'invalid email' })
    }
    if (await !argon2.verify(user.password, password)) {
      return res.status(402).json({ error: 'invalid password' })
    }
    const tokenPayload = {
      name: user.name,
      email: user.email,
      user_id: user.user_id,
      api_key_val: user.api_key.api_key_val,
      plan_name: user.api_key.api_plan.plan_name,
      plan_limit: user.api_key.api_plan.plan_limit
    };
    const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '1h' })
    res.status(200).json({ token, user })
  }
  catch (err) {
    if (err instanceof z.ZodError) {
      const errorMessages = err.errors.map(e => e.message).join(', ')
      return res.status(400).json({ error: errorMessages })
    }
    console.error('Internal Server Error:', err);
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization
  if (authHeader) {
    const token = authHeader.split(' ')[1]
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        return res.sendStatus(403)
      }
      req.user = user
      next()
    })
  } else {
    res.sendStatus(401)
  }
}

app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    res.status(200).json(req.user)
  } catch (err) {
    console.error('Internal Server Error:', err)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.post('/profile/regenerate', authenticateJWT, async (req, res) => {
  try {
    const email = req.user.email
    const rUser = req.user
    const user = await prisma.api_user.findUnique({
      where: { email },
      include: { api_key: true }
    });

    if ( rUser.api_key_val !== user.api_key.api_key_val) {
      return res.status(404).json({ error: 'Token not matching with database' });
    }
    const newApiKeyVal = require('crypto').randomUUID();

    const updatedApiKey = await prisma.api_key.update({
      where: { api_key_val: rUser.api_key_val },
      data: { api_key_val: newApiKeyVal }
    });
    const tokenPayload = {
      name: rUser.name,
      email: rUser.email,
      user_id: rUser.user_id,
      api_key_val: updatedApiKey.api_key_val,
      plan_name: rUser.plan_name,
      plan_limit: rUser.plan_limit
    };
    const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '1h' })
    res.status(200).json({ token , api_key: updatedApiKey });
  } catch (err) {
    console.error('Internal Server Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/api/crypto', async (req, res) => {
  try {
    const { api_key_val } = apiCryptoSchema.parse(req.body)
    const api = await prisma.api_key.findUnique({
      where: {
        api_key_val
      },
      include: {
        api_logs: true
      }
    })
    if (!api) {
      return res.status(403).json({ error: 'invalid api key' })
    }
    const now = new Date()
    const firstDayMonth = new Date(now.getFullYear(), now.getMonth(), 1)
    const lastDayMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0)
    const credit = await prisma.api_logs.aggregate({
      _sum: {
        credit_cost: true
      },
      where: {
        log_key_id: api.api_key_id,
        used_date: {
          gte: firstDayMonth,
          lt: lastDayMonth
        }
      }
    })
    const usedCredit = credit._sum.credit_cost
    const plan = prisma.api_plan.findUnique({
      where: {
        log_key_id: api.api_key_id
      }
    })
    if (usedCredit > plan.plan_limit) {
      return res.status(404).json({ error: 'credit limit reached' })
    }
    const response = await axios.get('http://10.94.0.1:5501/crypto/listing/local?page=0&pageSize=100&convert=USD,MNT,CNY,BTC');
    const responseData = response.data;
    res.status(200).json({ responseData })
  }
  catch (err) {
    if (err instanceof z.ZodError) {
      const errorMessages = err.errors.map(e => e.message).join(', ')
      return res.status(400).json({ error: errorMessages })
    }
    console.error('Internal Server Error:', err);
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})