package main

import (
	"myproject/database"
	"myproject/handlers"
	"myproject/middleware"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	defer database.DB.Close()

	router := mux.NewRouter()

	protectedRoutes := router.PathPrefix("/users").Subrouter()
	protectedRoutes.Use(middleware.AuthMiddleware)
	protectedRoutes.HandleFunc("", handlers.ListUsers).Methods("GET")
	protectedRoutes.HandleFunc("/{id}", handlers.GetUser).Methods("GET")
	protectedRoutes.HandleFunc("", handlers.CreateUser).Methods("POST")
	protectedRoutes.HandleFunc("/{id}", handlers.UpdateUser).Methods("PUT")
	protectedRoutes.HandleFunc("/{id}", handlers.DeleteUser).Methods("DELETE")

	router.HandleFunc("/login", handlers.Login).Methods("POST")

	http.ListenAndServe(":8000", router)
}
