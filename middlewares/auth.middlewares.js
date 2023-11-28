const jwt = require("jsonwebtoken")

function isTokenValid (req, res, next) {

  // investigamos como el cliente envia el token
  // console.log(req.headers) // aqui se transmite la info de autenticación

  try {
    // extraer el token de el string "Bearer XZSFV"
    // verificamos el token con jwt
    // decidimos que hacer con el usuario
    const token = req.headers.authorization.split(" ")[1]
    // const token = req.headers.authorization.replace("Bearer ", "")
    // el split regresa ["Bearer", "XZSFV"]
    
    const payload = jwt.verify(token, process.env.TOKEN_SECRET)
    // 1. el .verify valida el token
    // 2. el .verify nos devuelve el payload decifrado

    req.payload = payload // esto almacena el payload en req.payload y nos permite acceder en cualquier ruta donde pasemos el middleware isTokenValid
  
    next() // continua con la ruta
  } catch (error) {
    // 1. El token no existe
    // 2. El token sea invalido
    // 3. No existan headers en la llamada
    res.status(401).json("El token no existe o es invalido")
  }

}

module.exports = isTokenValid