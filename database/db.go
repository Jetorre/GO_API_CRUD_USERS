package database

import (
	"fmt"
	"log"
	"os"
	"strings"
	"ws_users/utils"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
)

var DB *sqlx.DB

func InitDB() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	//cargar variables de entorno
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	dbEnc := os.Getenv("BD_ENC")
	key := os.Getenv("MKE")
	realKey := key[5:37]
	crypto := utils.NewCryptoUtils(realKey)

	switch strings.ToUpper(dbEnc) { //switch para verificar el tipo de encriptacion
	case "CHANGE":

		utils.SecretFile()

	case "TRUE":
		dbUser, err = crypto.Decrypt(dbUser)
		dbUser = strings.TrimSpace(dbUser)
		if err != nil {
			log.Fatal("Error al descifrar el userName:", err)
		}
		dbPass, err = crypto.Decrypt(dbPass)
		dbPass = strings.TrimSpace(dbPass)
		if err != nil {
			log.Fatal("Error al descifrar el password:", err)
		}
		dbHost, err = crypto.Decrypt(dbHost)
		dbHost = strings.TrimSpace(dbHost)
		if err != nil {
			log.Fatal("Error al descifrar el HostName:", err)
		}
		dbPort, err = crypto.Decrypt(dbPort)
		dbPort = strings.TrimSpace(dbPort)
		if err != nil {
			log.Fatal("Error al descifrar el Puerto de conexión:", err)
		}
		dbName, err = crypto.Decrypt(dbName)
		dbName = strings.TrimSpace(dbName)
		if err != nil {
			log.Fatal("Error al descifrar el nombre de la BD:", err)
		}

	default:

	}
	var erro error
	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", dbUser, dbPass, dbHost, dbPort, dbName)
	DB, erro = sqlx.Open("mysql", dsn)
	if erro != nil {
		log.Fatal("Error al abrir la conexion con la  BD: ", erro)
		panic(erro)
	}

	erro = DB.Ping()
	if erro != nil {
		log.Fatal("Error en la Conexion con la BD: ", erro)
		panic(erro)
	}

	fmt.Println("Database connected!")
}
