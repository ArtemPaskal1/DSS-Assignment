package main

import (
	"database/sql"
	"encoding/json"
	"fmt" // Добавили этот импорт
	"log"
	"net/http"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v4/stdlib"
	"golang.org/x/crypto/bcrypt"
)

// User представляет структуру данных для пользователей
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// Comment представляет структуру данных для комментариев
type Comment struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

func main() {
	// Connect to PostgreSQL
	connStr := "postgres://postgres:Gafentiy@localhost/socialmedia?sslmode=disable"
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Run migrations
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		log.Fatal(err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}

	// Setup HTTP router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/register", registerHandler(db)).Methods("POST")
	router.HandleFunc("/login", loginHandler(db)).Methods("POST")
	router.HandleFunc("/comments", createCommentHandler(db)).Methods("POST")
	router.HandleFunc("/comments/{id}", getCommentHandler(db)).Methods("GET")
	router.HandleFunc("/comments/{id}", updateCommentHandler(db)).Methods("PUT")
	router.HandleFunc("/comments/{id}", deleteCommentHandler(db)).Methods("DELETE")
	router.HandleFunc("/admin/login", adminLoginHandler).Methods("POST")

	// Apply admin authentication middleware to protected routes
	router.Use(adminAuthMiddleware)

	// Start HTTP server
	log.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// registerHandler создает нового пользователя
func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		user.Password = string(hashedPassword)

		_, err = db.Exec("INSERT INTO users (username, password, created_at) VALUES ($1, $2, $3)", user.Username, user.Password, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// loginHandler аутентифицирует пользователя
func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var storedUser User
		err = db.QueryRow("SELECT id, username, password, created_at FROM users WHERE username = $1", user.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password, &storedUser.CreatedAt)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Authentication successful
		w.WriteHeader(http.StatusOK)
	}
}

// createCommentHandler создает новый комментарий
func createCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var comment Comment
		err := json.NewDecoder(r.Body).Decode(&comment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Вставить комментарий в базу данных
		_, err = db.Exec("INSERT INTO comments (user_id, content, created_at) VALUES ($1, $2, $3)", comment.UserID, comment.Content, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

// getCommentHandler возвращает комментарий по его идентификатору
func getCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Извлечение идентификатора комментария из URL
		params := mux.Vars(r)
		commentID := params["id"]

		// Запросить комментарий из базы данных по его идентификатору
		var comment Comment
		err := db.QueryRow("SELECT id, user_id, content, created_at FROM comments WHERE id = $1", commentID).Scan(&comment.ID, &comment.UserID, &comment.Content, &comment.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Отправить комментарий в качестве ответа
		json.NewEncoder(w).Encode(comment)
	}
}

// updateCommentHandler обновляет существующий комментарий
func updateCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Извлечение идентификатора комментария из URL
		params := mux.Vars(r)
		commentID := params["id"]

		// Распаковка JSON запроса в структуру Comment
		var updatedComment Comment
		err := json.NewDecoder(r.Body).Decode(&updatedComment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Обновление комментария в базе данных
		_, err = db.Exec("UPDATE comments SET content = $1 WHERE id = $2", updatedComment.Content, commentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// deleteCommentHandler удаляет комментарий по его идентификатору
func deleteCommentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Извлечение идентификатора комментария из URL
		params := mux.Vars(r)
		commentID := params["id"]

		// Удаление комментария из базы данных
		_, err := db.Exec("DELETE FROM comments WHERE id = $1", commentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// adminLoginHandler обрабатывает запрос на вход администратора
func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Извлечение имени пользователя и пароля из запроса
	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authorization failed", http.StatusUnauthorized)
		return
	}

	// Проверка имени пользователя и пароля
	if username != "admin" || password != "adminpassword" {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Верификация успешна, выдаем токен аутентификации
	// Здесь вы можете использовать JWT или любой другой механизм аутентификации по вашему выбору
	// Для простоты давайте просто вернем успешный статус
	w.WriteHeader(http.StatusOK)
}

// adminAuthMiddleware проверяет аутентификацию администратора перед выполнением защищенных операций
func adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Здесь должна быть логика для проверки аутентификации администратора
		// Для примера, давайте предположим, что у нас есть функция isAuthenticatedAdmin
		if !isAuthenticatedAdmin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAuthenticatedAdmin проверяет, является ли пользователь аутентифицированным администратором
func isAuthenticatedAdmin(r *http.Request) bool {
	// Реализация проверки аутентификации администратора
	// Для простоты, предположим, что администратор аутентифицирован
	return true
}

// renderTemplate генерирует HTML-страницу с указанным шаблоном и данными
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	var html string

	// Определяем HTML-код для шаблона
	switch tmpl {
	case "register":
		html = `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Register</title>
			</head>
			<body>
				<h2>Register</h2>
				<form action="/register" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username"><br>
					<label for="password">Password:</label><br>
					<input type="password" id="password" name="password"><br><br>
					<input type="submit" value="Register">
				</form>
			</body>
			</html>
		`
	case "login":
		html = `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Login</title>
			</head>
			<body>
				<h2>Login</h2>
				<form action="/login" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username"><br>
					<label for="password">Password:</label><br>
					<input type="password" id="password" name="password"><br><br>
					<input type="submit" value="Login">
				</form>
			</body>
			</html>
		`
	default:
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Отправляем HTML-страницу в ответ
	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprint(w, html); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
