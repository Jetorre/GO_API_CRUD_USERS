package handlers

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"ws_users/database"
	"ws_users/models"
	"ws_users/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func UpdateUser(c echo.Context) error {
	user := new(models.User)
	if err := c.Bind(user); err != nil {
		return err
	}

	query := `UPDATE users SET name=?, surname=?, email=?, phone=?, position=?, company=? WHERE id=?`
	_, err := database.DB.Exec(query, user.Name, user.Surname, user.Email, user.Phone, user.Position, user.Company, user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, user)
}

// Login autentica un usuario usando autenticación Bearer y genera un token JWT
// @Summary Registra un nuevo usuario
// @Description Agrega un nuevo usuario usando JWT
// @Tags consumos
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer Token"
// @Param user body models.User true "User Information"
// @Success 201 {object} models.User
// @Failure 400 {object} models.Error "Bad Request"
// @Failure 401 {object} models.Error "Unauthorized"
// @Security BearerAuth
// @Router /NewUser [post]
func RegisterUser(c echo.Context) error {
	er_response := new(models.Error)
	user := new(models.User)
	if err := c.Bind(user); err != nil {
		return err
	}

	if len(string(user.Password)) == 0 {
		er_response.Error = "password is required"
		return c.JSON(http.StatusInternalServerError, er_response)
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		er_response.Error = "Error hashing password"
		return c.JSON(http.StatusInternalServerError, er_response)
	}
	user.Password = string(hashedPassword)

	query := `INSERT INTO users (name, surname, email, phone, position, company, password) VALUES (?, ?, ?, ?, ?, ?, ?)`
	result, err := database.DB.Exec(query, user.Name, user.Surname, user.Email, user.Phone, user.Position, user.Company, user.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}
	// Get the last inserted ID
	userID, err := result.LastInsertId()
	if err != nil {
		er_response.Error = "Error retrieving last inserted ID"
		return c.JSON(http.StatusInternalServerError, er_response)
	}

	// Prepare the response
	user.ID = int(userID)
	var users models.Users
	users.ID = user.ID
	users.Name = user.Name
	users.Email = user.Email

	return c.JSON(http.StatusCreated, users)
}

func DeleteUser(c echo.Context) error {
	user := new(models.User)
	answer := new(models.Answer)
	if err := c.Bind(user); err != nil {
		return err
	}
	query := `delete from users WHERE id=?`
	_, err := database.DB.Exec(query, user.ID)
	if err != nil {
		answer.Message = err.Error()
		answer.Id = user.ID
		answer.Status = "Error"
		return c.JSON(http.StatusInternalServerError, answer)
	}
	answer.Message = "Registro eliminado correctamente"
	answer.Id = user.ID
	answer.Status = "Success"
	return c.JSON(http.StatusOK, answer)
}

func GetUsers(c echo.Context) error {

	answer := new(models.Answer)
	query := `select id,name,email from users`
	data_users, err := database.DB.Query(query)
	if err != nil {
		answer.Message = err.Error()
		answer.Id = 0
		answer.Status = "Error"
		return c.JSON(http.StatusInternalServerError, answer)
	}

	var users []models.Users

	// Leer los datos de la consulta y mapearlos a la estructura
	for data_users.Next() {
		var user models.Users
		err := data_users.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			answer.Message = err.Error()
			answer.Id = 0
			answer.Status = "Error"
			return c.JSON(http.StatusInternalServerError, answer)
		}
		users = append(users, user)
	}

	// Comprobar errores después de la iteración
	if err = data_users.Err(); err != nil {
		answer.Message = err.Error()
		answer.Id = 0
		answer.Status = "Error"
		return c.JSON(http.StatusInternalServerError, answer)
	}

	// Devolver la lista de usuarios como JSON
	return c.JSON(http.StatusOK, users)
}

// GetUser obtiene un solo usuario por ID
// @Summary Obtiene un solo usuario
// @Description Recupera un usuario basado en su ID proporcionada en la ruta
// @Tags consumos
// @Accept json
// @Produce json
// @Param id path int true "ID del Usuario"
// @Param Authorization header string true "Bearer Token"
// @Success 200 {object} []models.Users
// @Failure 401 {object} models.Error "Unauthorized"
// @Failure 500 {object} models.Error "Internal Server Error"
// @Security BearerAuth
// @Router /GetUser/{id} [get]
func GetUser(c echo.Context) error {
	id := c.Param("id") //QueryParam("id")
	answer := new(models.Answer)
	query := `select id, name, email from users where id = ?`
	data_users, err := database.DB.Query(query, id)
	if err != nil {
		answer.Message = err.Error()
		answer.Id = 0
		answer.Status = "Error"
		return c.JSON(http.StatusInternalServerError, answer)
	}

	var users []models.Users

	// Leer los datos de la consulta y mapearlos a la estructura
	for data_users.Next() {
		var user models.Users
		err := data_users.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			answer.Message = err.Error()
			answer.Id = 0
			answer.Status = "Error"
			return c.JSON(http.StatusInternalServerError, answer)
		}
		users = append(users, user)
	}

	// Comprobar errores después de la iteración
	if err = data_users.Err(); err != nil {
		answer.Message = err.Error()
		answer.Id = 0
		answer.Status = "Error"
		return c.JSON(http.StatusInternalServerError, answer)
	}

	// Devolver la lista de usuarios como JSON
	return c.JSON(http.StatusOK, users)
}

// Login autentica un usuario usando autenticación básica y genera un token JWT
// @Summary Autentica un usuario
// @Description Autentica un usuario usando autenticación básica y genera un token JWT
// @Tags autenticación
// @Accept json
// @Produce json
// @Success 200 {object} models.Token
// @Failure 401 {object} models.Error
// @Security BasicAuth
// @Router /login [post]
func Login(c echo.Context) error {
	er_response := new(models.Error)
	token_response := new(models.Token)
	auth := c.Request().Header.Get("Authorization")
	if auth == "" {
		er_response.Error = "Authorization header missing"
		return c.JSON(http.StatusUnauthorized, er_response)
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		er_response.Error = "Invalid Authorization header"
		return c.JSON(http.StatusUnauthorized, er_response)
	}

	payload, _ := base64.StdEncoding.DecodeString(parts[1])
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		er_response.Error = "Invalid Authorization value"
		return c.JSON(http.StatusUnauthorized, er_response)
	}

	email, password := pair[0], pair[1]

	user := new(models.User)
	err := database.DB.Get(user, "SELECT * FROM users WHERE email=?", email)
	if err != nil {
		er_response.Error = "Invalid email or password"
		return c.JSON(http.StatusUnauthorized, er_response)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		er_response.Error = "Invalid email or password"
		return c.JSON(http.StatusUnauthorized, er_response)
	}

	token, err := generateJWT(user, c)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}
	token_response.Token = token
	return c.JSON(http.StatusOK, token_response)
}

// JWTCustomClaims son los claims personalizados para el JWT
type JWTCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

/*
func generateJWT(user *models.User, c echo.Context) (string, error) {
	// Generar un UUID para el token
	id_t, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"id":      id_t.String(), // Agregar el UUID al token
		"exp":     time.Now().Add(1 * time.Minute).Unix(),
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatalf("JWT_SECRET_KEY no está configurado en las variables de entorno")
	}

	key := os.Getenv("MKE")
	if len(key) < 37 {
		log.Fatalf("La longitud de MKE es insuficiente para generar la clave secreta")
	}

	realKey := key[5:37]
	crypto := utils.NewCryptoUtils(realKey)

	// Desencripta el secret key
	decryptedSecretKey, err := crypto.Decrypt(secretKey)
	if err != nil {
		log.Fatalf("Error al descifrar el JWT_SECRET_KEY: %v", err)
	}

	if strings.TrimSpace(decryptedSecretKey) == "" {
		log.Fatalf("La clave secreta descifrada está vacía")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(decryptedSecretKey))
	if err != nil {
		return "", err
	}
	query := `CALL app.InsertToken(?, ?)`
	_, err = database.DB.Exec(query, tokenString, user.ID)
	if err != nil {
		log.Fatal("Error al almacenar el token", err)
	}
	return tokenString, nil
}*/

func generateJWT(user *models.User, c echo.Context) (string, error) {
	// Generar un UUID para el token
	id_t, err := uuid.NewV4()
	if err != nil {
		return "", err
	}

	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		log.Fatalf("JWT_SECRET_KEY no está configurado en las variables de entorno")
	}

	key := os.Getenv("MKE")
	if len(key) < 37 {
		log.Fatalf("La longitud de MKE es insuficiente para generar la clave secreta")
	}

	realKey := key[5:37]
	crypto := utils.NewCryptoUtils(realKey)

	// Desencripta el secret key
	decryptedSecretKey, err := crypto.Decrypt(secretKey)
	if err != nil {
		log.Fatalf("Error al descifrar el JWT_SECRET_KEY: %v", err)
	}

	if strings.TrimSpace(decryptedSecretKey) == "" {
		log.Fatalf("La clave secreta descifrada está vacía")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"id":      id_t.String(), // Agregar el UUID al token
		"exp":     time.Now().Add(1 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString([]byte(decryptedSecretKey))
	if err != nil {
		return "", err
	}
	query := `CALL app.InsertToken(?, ?)`
	_, err = database.DB.Exec(query, tokenString, user.ID)
	if err != nil {
		log.Fatal("Error al almacenar el token", err)
	}
	return tokenString, nil
}
