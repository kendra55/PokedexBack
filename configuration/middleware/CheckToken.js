import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config(); // appelle-le une fois ici ou dans index.js

const checkToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ message: 'Token is required' });
  }

  // retirer le préfixe 'Bearer ' si présent
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token is not valid' });
    }

    req.user = decoded; // assigner la valeur décodée
    next();
  });
};

export default checkToken;
