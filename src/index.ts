import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';



const app = express();
const port = process.env.PORT || 3000;
const prisma = new PrismaClient();

app.use(express.json());
app.use(express.raw({ type: "application/vnd.custom-type" }));
app.use(express.text({ type: "text/html" }));


app.post("/user", async (req, res) => {  
    const {name,email,password} = req.body;
    if (!name) {
      return res.status(400).json({ message: 'O nome é obrigatório' })
    }  
    if (!email) {
      return res.status(400).json({ message: 'O e-mail é obrigatório' })
    }
    if (!email) {
      return res.status(400).json({ message: 'A senha é obrigatória' })
    }
    const userExists = await prisma.user.findFirst({where: {email: email}});
    if (userExists) {
      return res.status(400).json({ message: 'e-mail já cadastrado' })
    }
  
    const hashPassword = await bcrypt.hash(password, 10)
    
    try {
      const newUser = await prisma.user.create({
        data: {
          name,
          email,
          password: hashPassword 
        },
      }); 
      const { password: _, ...user } = newUser
  
      return res.json(user);
    } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error' })
    }
      
});

app.get("/users", async (req, res) => {  
    try {
      const users = await prisma.user.findMany({
          select: {
            password: false,
            name: true,
            email: true,
            createdAt: true
          },
          orderBy: [
            {
              createdAt: 'desc',
            },
          ]
          });
          res.json(users);
      } catch (error) {
        return res.status(500).json({ message: 'Internal Server Error' })
    }
});

app.post("/login", async (req, res) => {  
    const { email, password } = req.body
  
    const user = await prisma.user.findFirst({ where: { email: email }});
  
    if (!user) {
      return res.status(400).json({ message: 'e-mail/Senha inválidos' })
    }
    
    const verifyPass = await bcrypt.compare(password, user.password)
  
    if (!verifyPass) {
      return res.status(400).json({ message: 'e-mail/Senha inválidos' })
    }
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_PASS ?? '', {
      expiresIn: '8h',
    })
  
    const { password: _, ...userLogin } = user
  
    return res.json({
      user: userLogin,
      token: token,
    })
});

app.get("/", async (req, res) => {
  res.send(
    `
  <h1>User REST API</h1>
  `.trim(),
  );
});

app.listen(Number(port), "0.0.0.0", () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
