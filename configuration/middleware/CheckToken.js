import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

const checkToken = (req, res, next) => {

    dotenv.config();
    
    

    const token = req.headers['authorization'];


    if (!token) {
        return res.status(401).json({ message: 'Token is required' });
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(401).json({ message: 'Token is not valid' }); 
    } 

    req.user = decoded;
    next();
})}

export default checkToken;