const router = require("express").Router();

const User = require("../models/User.model");

const bcrypt = require("bcryptjs")

const jwt = require("jsonwebtoken")

const isTokenValid = require("../middlewares/auth.middlewares")

// POST "/api/auth/signup" => recibir data del usuario y lo crea en la BD
router.post("/signup", async (req, res, next) => {
  console.log(req.body)

  const { username, email, password } = req.body

  // implementariamos todas las validaciones de backend igual a M2

  if ( !username || !email || !password ) {
    res.status(400).json({ errorMessage: "Todos los campos deben estar llenos" })
    return // deten la ejecución de la ruta
  }

  // que la contraseña sea suficientemente segura
  // que el correo electronico tenga formato correcto
  // que el campo de nombre tenga una cantidad de caracteres correcta
  // etc... y todas estas validaciones, se les dejamos que las hagan ustedes en el proyecto :)

  try {
    
    const foundUser = await User.findOne({ email: email })
    if (foundUser) {
      res.status(400).json({ errorMessage: "Correo electronico ya registrado" })
      return // deten la ejecución de la ruta
    }

    // validar tambien que el username no se pueda duplicar... de tarea.

    // cifrar la contraseña
    const salt = await bcrypt.genSalt(12)
    const hashPassword = await bcrypt.hash(password, salt)
    console.log(hashPassword)


    // despues de todas las validaciones y cifrar la contraseña creamos el usuario
    await User.create({
      username,
      email,
      password: hashPassword
    })

    res.status(201).json("usuario creado")

  } catch (error) {
    next(error)
  }

})

// POST "/api/auth/login" => recibir credenciales del usuario y validarlo
router.post("/login", async (req, res, next) => {

  console.log(req.body)
  const { email, password } = req.body

  if ( !email || !password ) {
    res.status(400).json({ errorMessage: "Todos los campos deben estar llenos" })
    return // deten la ejecución de la ruta
  }

  try {

    const foundUser = await User.findOne({ email: email })
    if (!foundUser) {
      res.status(400).json({errorMessage: "Usuario no registrado"})
      return
    }

    const isPasswordValid = await bcrypt.compare(password, foundUser.password)
    if (!isPasswordValid) {
      res.status(400).json({errorMessage: "Contraseña no valida"})
      return
    }

    // si todo sale bien este es el momento en donde creariamos una sesion activa del usuario

    // sin embargo, hoy aprenderemos un nuevo tipo de autenticacion ;)

    // creamos el payload => toda la información que identifica al usuario
    // agregamos información que no deberia cambiar
    const payload = {
      _id: foundUser._id,
      email: foundUser.email,
      // ! si tuvieramos roles, los agregamos tambien
    }

    const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: '2d' }) // 2 días como ejemplo

    res.json({ authToken: authToken })


  } catch (error) {
    next(error)
  }

})

// GET "/api/auth/verify" => Indicar al FE si está que visila la pagina está activo y quien es
router.get("/verify", isTokenValid, (req, res, next) => {

  // ! por medio del req.payload, el SERVIDOR (EXPRESS) sabe quien es el usuario que está haciendo las llamadas
  console.log(req.payload)

  // 1. valida el token del usuario
  // 2. recibe el payload
  // 3. envia el payload al lado del cliente. 
  // -  indica si el usuario esta logeado o no
  // -  si esta logeado, indica que usuario es

  res.json({ payload: req.payload })
  // ! se envie el payload para que el CLIENTE (REACT) sepa quien es el usuario que está navegando y su status

})


module.exports = router;