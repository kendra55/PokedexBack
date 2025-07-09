import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../configuration/bd.js';
import dotenv from "dotenv";
import checkToken from '../configuration/middleware/CheckToken.js';

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

        if (result.length > 0 ){

            const checkPassword = await bcrypt.compare(password, userData.password);
            
            if (checkPassword == true){

                // création du token
                const token = jwt.sign
                ({idUser: userData.idUser, username: userData.name},
                     process.env.SECRET_KEY,
                      {expiresIn: "12h"});

                res.status(201).json({
                    message: "connexion autorisé",
                    token: token,
                    user: {
                       id: userData.idUser,
                       name: userData.name,
                     mail: mail
                      }
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
router.get('/profile', checkToken, async (req, res) => {
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

// route pour modifier le profile utilisateur authentifié
router.put('/profile/update', checkToken, async (req, res) => {
    // récupération des information utilisateur
    const {name, mail} = req.body;
    const userId = req.user.idUser;
    const updateUser = "UPDATE Users SET name= ?, mail= ? where idUser =?;";

    try { //db. query sert a executer une requete SQL (donc faire une recherche dans la base de données)
        await db.query(updateUser, [name, mail, userId])
        res.status(200).json({ message: "profile modifié"});
        
    } catch (error) {
        // gestion en cas d'erreur
        res.status(500).json({message: "erreur lors de la modification du profile", error})
        
    }
});

router.put('/profile/password/update', checkToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.idUser;

    try {
        // 1. Récupérer le password actuel en base
        const selectUser = "SELECT password FROM users WHERE idUser = ?";
        const [rows] = await db.query(selectUser, [userId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: "utilisateur introuvable" });
        }

        const currentPassword = rows[0].password;

        // 2. Vérifier l'ancien mot de passe
        const isMatch = await bcrypt.compare(oldPassword, currentPassword);
        if (!isMatch) {
            return res.status(403).json({ message: "ancien mot de passe incorrect" });
        }

        // 3. Hasher le nouveau mot de passe
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // 4. Mettre à jour le mot de passe
        const updatePassword = "UPDATE users SET password = ? WHERE idUser = ?";
        await db.query(updatePassword, [hashedNewPassword, userId]);

        res.status(200).json({ message: "mot de passe modifié avec succès" });

    } catch (error) {
        res.status(500).json({ message: "erreur lors de la modification du mot de passe", error });
        console.log(error);
    }
});

export default router;  