package middleware

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"ws_users/utils"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Función para verificar el estado del token en la base de datos
func CheckTokenStatus(db *sql.DB, tokenID string) (bool, error) {
	var status int
	dbconsulta := fmt.Sprintf("CALL CheckTokenStatus('%s')", tokenID)
	// Consulta a la base de datos para verificar el estado del token
	err := db.QueryRow(dbconsulta).Scan(&status)
	log.Println("valida token recibido - 1 solo uso")
	if err != nil {
		return false, err
	}
	if status == 1 {
		log.Println("Token Valido")
		return true, nil
	} else {
		log.Println("Token invalido")
		return false, err
	}

}

// Middleware JWT que valida el token y su estado
func JWTMiddleware(db *sql.DB) echo.MiddlewareFunc {
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

	return middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte(decryptedSecretKey),
		Claims:     &jwt.MapClaims{},
		AuthScheme: "Bearer",
	})
}

// Middleware JWT que valida el token y su estado
// Middleware que valida el estado del token y lo desactiva después de su uso
func TokenValidationMiddleware(db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user")
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token no proporcionado")
			}

			token, ok := user.(*jwt.Token)
			if !ok || !token.Valid {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token inválido")
			}
			//--------------------------------
			// Decodifica el token sin verificar la firma

			tokenString := c.Request().Header.Get("Authorization")
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")

			token, err := jwt.Parse(tokenString, nil)
			if err != nil && !strings.Contains(err.Error(), "Keyfunc") {
				log.Println("Error al decodificar el token:", err)
			}

			// Accede a los claims
			if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				log.Println("Validacion de Token con Claims OK")
			} else {
				//log.Println("Token con Claims inválido")
			}
			//--------------------------------
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "ID del token faltante o inválido")
			}

			// Verifica el estado del token en la base de datos
			active, err := CheckTokenStatus(db, tokenString)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Error al verificar el estado del token")
			}
			if !active {
				return echo.NewHTTPError(http.StatusUnauthorized, "Token ya utilizado o inactivo")
			}

			// Desactiva el token después de su uso
			if err := DeactivateToken(db, tokenString); err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "Error al desactivar el token")
			}

			return next(c)
		}
	}
}

// Función para desactivar el token usando el procedimiento almacenado
func DeactivateToken(db *sql.DB, tokenID string) error {
	dbconsulta := fmt.Sprintf("CALL SetTokenInactive('%s')", tokenID)
	_, err := db.Exec(dbconsulta)
	return err
}
