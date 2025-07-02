import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../configuration/bd.js';
import dotenv from "dotenv";

// création du router permettant de gérer les routes liées aux utilisateurs
const router = express.Router();
dotenv.config();

    // route d'inscription utilisateur
router.post('/register', async (req, res) => {
    // récupération des information utilisateur
    const {name, mail, password} = req.body;
    // préparation de la requete
    const insertUser = "INSERT INTO users (name, mail, password) VALUES (?,?,?);";

    try {
        // cryptage du password
        const cryptedPassword = await bcrypt.hashSync(password, 10);

        // utilisation de la connexion bdd pour executer la requete
        await db.query(insertUser, [name, mail, cryptedPassword])
        res.status(201).json({ message: "utilisateur créé"});
        
    } catch (error) {
        // gestion en cas d'erreur
        res.status(500).json({message: "erreur lors de l'inscription", error})
        
    }
});

// route de connexion
router.post('/login', async (req, res) => {
    const {mail, password} = req.body;
    const selectUser = "SELECT idUser, name, password from users where mail like ?;";

    try{

        const [result] = await db.query(selectUser, [mail])

        const userData = result[0];

        if (result){

            const checkPassword = await bcrypt.compare(password, userData.password);
            
            if (checkPassword == true){

                // création du token
                const token = jwt.sign({idUser: userData.idUser, username: userData.name}, process.env.SECRET_KEY, {expiresIn: "1h"});

                res.status(201).json({
                    message: "connexion autorisé",
                    token: token
                });
            } else {
                res.status(403).json({message: "accès refusé"});
            }

        } else {
            res.status(104).json({message: "utilisateur inconnu"})
        }

    } catch (error) {

        res.status(500).json({message: "erreur lors de la connexion", error})
        console.log(error);

    }
});

// route pour récupérer le profile utilisateur authentifié
router.get('/profile', async (req, res) => {
    // récupération du token pour avoir l'autaurisation de récupérer les information l'utilisateur
    const userId = req.user.idUser;


 const getProfile = "SELECT idUser, name, mail from users where idUser =?;";

 try {

    const [result] = await db.query(getProfile, [userId])

    if (result.length > 0){
        res.status(200).json(result[0]);
    } else {    
        res.status(404).json({message: "utilisateur introuvable"})
   
 }
    
 } catch (error) {
    res.status(500).json({message: "erreur lors de la récupération du profile", error})
    console.log(error);
 }
})

export default router;
