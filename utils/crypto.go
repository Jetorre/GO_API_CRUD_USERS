package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// CryptoUtils es la estructura que contendrá la clave para cifrar y descifrar
type CryptoUtils struct {
	Key []byte
}

// NewCryptoUtils crea una nueva instancia de CryptoUtils con la clave dada
func NewCryptoUtils(key string) *CryptoUtils {
	return &CryptoUtils{
		Key: []byte(key),
	}
}

// Encrypt cifra el texto dado utilizando AES
func (c *CryptoUtils) Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt descifra el texto cifrado utilizando AES
func (c *CryptoUtils) Decrypt(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("data is too short")
	}

	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:] // Cambié el nombre aquí para evitar conflicto con el parámetro
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	// Aquí se hace la conversión de []byte a string
	return string(plainText), nil
}
