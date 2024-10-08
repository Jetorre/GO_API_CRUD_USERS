package utils

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func SecretFile() {
	// Leer clave de cifrado
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	//cargar variables de entorno
	key := os.Getenv("MKE")
	realKey := key[5:37]
	crypto := NewCryptoUtils(realKey)

	// Leer el archivo .env
	fileName := ".env"
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("Error al abrir el archivo .env: %v\n", err)
		return
	}
	defer file.Close()

	// Crear un archivo temporal para almacenar los valores cifrados
	tempFileName := ".env.tmp"
	tempFile, err := os.Create(tempFileName)
	if err != nil {
		fmt.Printf("Error al crear el archivo temporal: %v\n", err)
		return
	}
	defer tempFile.Close()

	// Leer línea por línea y cifrar los valores
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MKE") {
			fmt.Fprintf(tempFile, "%s\n", line)

		} else {
			if strings.HasPrefix(line, "BD_ENC") {
				str_bd_enc := "BD_ENC = true"
				fmt.Fprintf(tempFile, "%s\n", str_bd_enc)
			} else {
				if strings.Contains(line, "=") {
					// Separar clave y valor
					parts := strings.SplitN(line, "=", 2)
					if len(parts) != 2 {
						fmt.Printf("Formato de línea inválido: %s\n", line)
						continue
					}
					key := parts[0]
					value := parts[1]

					// Cifrar el valor
					encryptedValue, err := crypto.Encrypt(value)
					if err != nil {
						fmt.Printf("Error al cifrar el valor %s: %v\n", value, err)
						continue
					}

					// Escribir clave y valor cifrado en el archivo temporal
					_, err = fmt.Fprintf(tempFile, "%s=%s\n", key, encryptedValue)
					if err != nil {
						fmt.Printf("Error al escribir en el archivo temporal: %v\n", err)
						return
					}
				} else {
					// Copiar líneas que no contienen "=", como comentarios
					_, err = fmt.Fprintln(tempFile, line)
					if err != nil {
						fmt.Printf("Error al escribir en el archivo temporal: %v\n", err)
						return
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error al leer el archivo .env: %v\n", err)
		return
	}

	// Cerrar los archivos
	file.Close()
	tempFile.Close()

	// Intentar renombrar el archivo varias veces
	for i := 0; i < 5; i++ {
		err = os.Rename(tempFileName, fileName)
		if err == nil {
			fmt.Println("Archivo .env reemplazado exitosamente.")
			return
		}

		fmt.Printf("Error al renombrar, intento %d: %v\n", i+1, err)
		time.Sleep(1 * time.Second) // Esperar 1 segundo antes de reintentar
	}

	fmt.Printf("Error al reemplazar el archivo .env después de varios intentos: %v\n", err)

}
