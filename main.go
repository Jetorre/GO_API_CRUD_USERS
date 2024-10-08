package main

import (
	"log"
	"os"
	"ws_users/database"
	_ "ws_users/docs"
	"ws_users/handlers"
	"ws_users/middleware"

	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title API de Usuarios
// @version 1.0
// @description Esta es una API para gestionar usuarios.
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.basic BasicAuth

func main() {
	// Abrir o crear el archivo de log
	file, err := os.OpenFile("logfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Error al abrir el archivo de log: %v", err)
	}
	defer file.Close()

	// Configurar el logger para escribir en el archivo
	log.SetOutput(file)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	database.InitDB()

	e := echo.New()
	// Ruta para la documentación de Swagger
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.POST("/api/v1/login", handlers.Login)

	r := e.Group("/api/v1")
	r.Use(middleware.JWTMiddleware(database.DB.DB))
	r.Use(middleware.TokenValidationMiddleware(database.DB.DB))

	r.POST("/NewUser", handlers.RegisterUser)

	r.PUT("/user", handlers.UpdateUser)

	r.DELETE("/Delete", handlers.DeleteUser)

	r.GET("/GetUsers", handlers.GetUsers)

	r.GET("/GetUser/:id", handlers.GetUser)

	// Configurar el servidor HTTPS
	certFile := "C:/GO/ws_users/cert.pem"
	keyFile := "C:/GO/ws_users/key.pem"

	// Iniciar el servidor HTTPS
	if err := e.StartTLS(":443", certFile, keyFile); err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
