import mysql from "mysql2/promise";
import dotenv from "dotenv";

// utilisation de dotenv pour charger les variables d'environnement
dotenv.config();

// création connexion à la base de données
const bdd = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});


export default bdd;