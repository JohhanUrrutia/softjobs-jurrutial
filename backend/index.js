import express from "express";
import cors from "cors";
import { handleErrors } from "./database/errors.js";
import { verifyToken } from "./database/verifyToken.js";
import bcrypt from "bcryptjs";
import morgan from "morgan";
import jwt from "jsonwebtoken";
import { getUser, registerUser, verifyUser } from "./database/methods.js";

const app = express();

app.use(express.json())
app.use(morgan("dev"))
app.use(cors())

app.get("/usuarios", verifyToken, async(req, res) => {
    const email = req.email
    try {
        const PeticionGetUser = await getUser({email})
        res.json(PeticionGetUser)

    } catch (error) {
        const { status, message } = handleErrors(error.code)
        return res.status(status).json({ ok: false, result: message})
    }
})


// Permite el registro de nuevos usuarios
app.post("/usuarios", async(req, res) => {

    const { email, password, rol, lenguaje } = req.body;

    try {

        if(!email || !password){
            // Se direcciona al catch
            throw({message: "Se necesita el email y contraseña."})
        }

        // Promise para hashear contraseña e insertarla en base de datos
        const hashPassword = await bcrypt.hash(password, 2)

        const PeticionRegisterUser = await registerUser({email, hashPassword, rol, lenguaje})
        res.json(PeticionRegisterUser)

    } catch (error) {
        const { status, message } = handleErrors(error.code)
        return res.status(status).json({ ok: false, result: message})
    }
})

// Recibe las credenciales de un usuario y devuelva un token generado con JWT
app.post("/login", async(req, res) => {

    const {email, password} = req.body;

    try {
        if(!email || !password){
            // Se direcciona al catch
            throw({message: "Se necesita el email y contraseña."})
        }
        // Verificar credenciales
        const PeticionVerifyUser = await verifyUser({email, password})
        res.json(PeticionVerifyUser)

        // Generar el JWT
        const token = jwt.sign({email}, "Estanoeslacontrasena")
        res.json(token)

    } catch (error) {
        const { status, message } = handleErrors(error.code)
        return res.status(status).json({ ok: false, result: message})
    }
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Servidor listo en http://localhost:" + PORT);
})