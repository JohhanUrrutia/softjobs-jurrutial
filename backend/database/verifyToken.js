import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
    console.log(req.headers)
    try {
        const bearerHeaders = req.headers.authorization
        if(!bearerHeaders){
            throw { message: "Se necesita el token con formato Bearer" }
        }
        const token = bearerHeaders.split(" ")[1]

        // Verificando el token entregado en POSTMAN
        const payload = jwt.verify(token, "Estanoeslacontrasena")

        req.email = payload.email;

        next()
    } catch (error) {
        console.log(error)
    }
}