package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// Create app
func main() {
    app := fiber.New()

    // Enable CORS 
    app.Use(cors.New())
	//dummy endpoint
    app.Get("/api/hello", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Hello from Go!",
        })

    })

    app.Listen(":8080")
}