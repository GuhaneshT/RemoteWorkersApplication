package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
)

// JWT secret key
var jwtSecret = []byte("razini69@123")

// Generate JWT token
func generateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // 1 hour expiry
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// JWT middleware to protect routes
func jwtMiddleware(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
	}

	// Parse the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return jwtSecret, nil
	})

	if err != nil || !parsedToken.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}
	// add username to context
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		c.Locals("username", claims["username"])
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	return c.Next()
}

// User struct to hold user data
type User struct {
	Username string
	Password string
	Email    string
	Score    int
}

// Dummy user store
var users = map[string]User{
	"rajini": {Username: "rajini", Password: "password123", Email: "rajini@example.com", Score: 120},
	"kamal":  {Username: "kamal", Password: "qwerty456", Email: "kamal@example.com", Score: 95},
}

// Main app
func main() {
	app := fiber.New()

	// Enable CORS
	app.Use(cors.New())

	app.Post("/api/login", loginHandler)
	app.Post("/api/signin", signinHandler)
	app.Post("/api/change-username-password", jwtMiddleware, changeUsernamePasswordHandler)
	app.Get("/api/user", jwtMiddleware, getUserDetails)

	app.Listen(":8080")
}

// Login Handler
func loginHandler(c *fiber.Ctx) error {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	user, ok := users[body.Username]
	if !ok || user.Password != body.Password {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials", "ok": user})
	}

	token, err := generateJWT(user.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"message":  "Login successful",
		"username": user.Username,
		"email":    user.Email,
		"score":    user.Score,
		"token":    token,
	})
}

// Signin Handler
func signinHandler(c *fiber.Ctx) error {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	if _, exists := users[body.Username]; exists {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
	}

	users[body.Username] = User{
		Username: body.Username,
		Password: body.Password,
		Email:    body.Email,
		Score:    0,
	}

	token, err := generateJWT(body.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"message":  "Sign in successful",
		"username": body.Username,
		"email":    body.Email,
		"score":    0,
		"token":    token,
	})
}

func getUserDetails(c *fiber.Ctx) error {
	username := c.Locals("username").(string)

	user, ok := users[username]
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{
		"username": user.Username,
		"email":    user.Email,
		"score":    user.Score,
	})
}

// Change Username and Password Handler
func changeUsernamePasswordHandler(c *fiber.Ctx) error {

	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewUsername string `json:"new_username"`
		NewPassword string `json:"new_password"`
	}

	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	user, ok := users[body.Username]
	if !ok || user.Password != body.Password {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Remove old user and add new one with updated credentials
	delete(users, body.Username)
	user.Username = body.NewUsername
	user.Password = body.NewPassword
	users[body.NewUsername] = user

	return c.JSON(fiber.Map{
		"message":      "Username and password changed successfully",
		"new_username": user.Username,
		"email":        user.Email,
		"score":        user.Score,
	})
}
