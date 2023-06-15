import pkg from "pg";
import bcrypt from "bcryptjs";
const {Pool} = pkg;

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'softjobs',
    password: 'root',
    port: 5432,
    allowExitOnIdle: true,
});

export const getUser = async({email}) => {

    const comando = "SELECT * FROM usuarios WHERE email = $1"
    const {rows} = await pool.query(comando, [email])
    return rows

}

export const registerUser = async({email, hashPassword, rol, lenguaje}) => {

    const comando = "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *"
    const {rows} = await pool.query(comando, [email, hashPassword, rol, lenguaje])
    return rows

}

export const verifyUser = async({email, password}) => {

    const comando = "SELECT * FROM usuarios WHERE email = $1"

    const {rows: [userDB], rowCount} = await pool.query(comando, [email])

    // Verifica si existe usuario
    if (!rowCount){
        console.log("No Existe Usuario")
        throw { message: "No Existe Usuario"}
    }

    const verifyPassword = await bcrypt.compare(password, userDB.password)

    // Verifica contraseña
    if (!verifyPassword){
        console.log("Contraseña incorrecta")
        throw { message: "Contraseña incorrecta"}
    }

    return userDB
}
    