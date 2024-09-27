
require("dotenv").config();
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors');
const app = express()

app.use(cors());
app.use(express.json())

const User = require('./models/User')

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS
const secret = process.env.SECRET


app.get("/user/:id", tokenCheck, async (req, res) => {
    const id = req.params.id

    if (!id) {
        return res.status(400).json({ message: "ID não fornecido." });
    }

    if (!mongoose.isValidObjectId(id)) {
        return res.status(400).json({ message: "ID inválido." });
    }

    const user = await User.findById(id, '-password')


    if (!user) {
        return res.status(404).json({ message: "Usuário não encontrado " })
    }

    res.status(200).json({ user })
})

function tokenCheck(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado!' })
    }

    try {
        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({ msg: "Token inválido!" })
    }
}

app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    const userInDatabase = await User.findOne({ email: email })

    if (!name) {
        return res.status(422).json({ message: 'Insira o nome de usuário' });
    }

    if (!email) {
        return res.status(422).json({ message: 'Insira o email' });
    }

    if (!password) {
        return res.status(422).json({ message: 'Insira a senha' });
    }

    if (userInDatabase) {
        return res.status(422).json({ message: 'Usuário existente' })
    }

    if (password.length < 8) {
        return res.status(422).json({ message: 'A senha deve ter no mínimo 8 caracteres.' });
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ message: 'As senhas não correspondem' });
    }


    const salt = await bcrypt.genSalt(12)
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: hashedPassword
    })

    try {
        await user.save()
        res.status(201).json({ message: 'Usuário criado com sucesso!' })
    } catch (error) {
        res.status(500).json({ message: `Erro do servidor ${error}` })
    }

});

app.post("/auth/login", async (req, res) => {
    const { email, password, } = req.body;

    if (!email) {
        return res.status(422).json({ message: 'Insira o email' });
    }

    if (!password) {
        return res.status(422).json({ message: 'Insira a senha' });
    }

    const userInDatabase = await User.findOne({ email: email })


    if (!userInDatabase) {
        return res.status(422).json({ message: 'Email inválido!' })
    }

    const checkPassword = await bcrypt.compare(password, userInDatabase.password)

    if (!checkPassword) {
        return res.status(404).json({ message: 'Senha errada, digite novamente!' });
    }

    try {
        const secret = process.env.secret
        const token = jwt.sign(
            {
                id: userInDatabase._id
            },
            secret,
        )
        res.status(200).json({ message: 'Login realizado com sucesso', token, userId: userInDatabase._id });
    } catch (error) {
        res.status(500).json({ message: `Erro do servidor ${error}` })
    }

})


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@autjwthugo.tw9g9.mongodb.net/`).then(() => {
    app.listen(3001)
}).catch((err) => {
    console.log(err, "error")
})