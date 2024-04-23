package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"myproject/database"
	"myproject/models"
	"myproject/utils"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query("SELECT id, name, email FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.ResponseUser
	for rows.Next() {
		var user models.ResponseUser
		if err := rows.Scan(&user.ID, &user.Name, &user.Email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	json.NewEncoder(w).Encode(users)
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar se o email já existe no banco de dados
	var count int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", user.Email).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Email already exists", http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Substituir a senha original pelo hash
	user.Password = hashedPassword

	_, err = database.DB.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", user.Name, user.Email, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User created successfully")
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	// Obter o parâmetro de ID da rota
	vars := mux.Vars(r)
	id := vars["id"]

	// Consulta SQL para buscar o usuário pelo ID
	query := "SELECT id, name, email FROM users WHERE id = ?"

	// Executar a consulta no banco de dados
	var user models.ResponseUser
	err := database.DB.QueryRow(query, id).Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		// Se ocorrer um erro ao buscar o usuário, retornar um erro 500
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Erro ao buscar usuário: %v", err)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Extrair o ID do usuário da solicitação
	vars := mux.Vars(r)
	id := vars["id"]

	// Decodificar o corpo da solicitação JSON para obter os novos dados do usuário
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar se o email já existe no banco de dados, excluindo o próprio usuário da contagem
	var count int
	err = database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", user.Email, id).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Email already exists", http.StatusBadRequest)
		return
	}

	query := "UPDATE users SET name = ?, email = ?"
	var queryParams []interface{}
	queryParams = append(queryParams, user.Name, user.Email)

	if user.Password != "" {
		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user.Password = hashedPassword
		query += ", password = ?"
		queryParams = append(queryParams, user.Password)
	}

	query += " WHERE id = ?"
	queryParams = append(queryParams, id)

	// Executar a atualização no banco de dados
	result, err := database.DB.Exec(query, queryParams...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verificar se a atualização afetou alguma linha
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Se nenhuma linha foi afetada, significa que o usuário com o ID fornecido não foi encontrado
	if rowsAffected == 0 {
		http.Error(w, "User not found or none changes", http.StatusNotFound)
		return
	}

	// Responder com sucesso
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User updated successfully"))
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Extrair o ID do usuário da solicitação
	vars := mux.Vars(r)
	id := vars["id"]

	// Executar a exclusão no banco de dados
	result, err := database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Responder com sucesso
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User deleted successfully"))
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar se o email existe no banco de dados e obter a senha armazenada
	var storedPassword, storedID string
	err = database.DB.QueryRow("SELECT password FROM users WHERE email = ?", user.Email).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Email not found", http.StatusUnauthorized)
		return
	}

	// Verificar se a senha fornecida corresponde à senha armazenada
	err = utils.VerifyPassword(storedPassword, user.Password)
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Gerar token JWT
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = storedID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token válido por 24 horas

	// Assinar o token com a chave secreta
	tokenString, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retornar o token JWT para o cliente
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}
