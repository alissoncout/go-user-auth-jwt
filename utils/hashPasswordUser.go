package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword gera um hash seguro da senha usando bcrypt
func HashPassword(password string) (string, error) {
	// Gerar hash da senha
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// VerifyPassword verifica se a senha fornecida corresponde ao hash da senha armazenada
func VerifyPassword(hashedPassword, password string) error {
	// Comparar hash da senha com a senha fornecida
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
