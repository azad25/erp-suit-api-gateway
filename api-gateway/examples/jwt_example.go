package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/auth"
	"erp-api-gateway/internal/cache"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create Redis cache (optional)
	redisCache := cache.NewRedisCache(&cfg.Redis)

	// Create JWT validator
	jwtValidator := auth.NewJWTValidator(&cfg.JWT, redisCache)

	// Create authentication middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtValidator, redisCache)

	// Setup Gin router
	router := gin.Default()

	// Public endpoints (no authentication required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	// Optional authentication endpoints
	router.GET("/profile", authMiddleware.OptionalJWT(), func(c *gin.Context) {
		if middleware.IsAuthenticated(c) {
			userID, _ := middleware.GetUserID(c)
			roles, _ := middleware.GetUserRoles(c)
			
			c.JSON(http.StatusOK, gin.H{
				"user_id": userID,
				"roles":   roles,
				"message": "Authenticated user profile",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"message": "Anonymous user profile",
			})
		}
	})

	// Protected endpoints (authentication required)
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware.RequireAuth())
	{
		// Basic protected endpoint
		protected.GET("/user", func(c *gin.Context) {
			claims, _ := middleware.GetUserClaims(c)
			c.JSON(http.StatusOK, gin.H{
				"user": gin.H{
					"id":          claims.UserID,
					"email":       claims.Email,
					"roles":       claims.Roles,
					"permissions": claims.Permissions,
				},
			})
		})

		// Admin-only endpoint
		protected.GET("/admin/users", func(c *gin.Context) {
			if !middleware.HasRole(c, "admin") {
				c.JSON(http.StatusForbidden, gin.H{
					"success": false,
					"message": "Admin role required",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"users": []gin.H{
					{"id": "1", "name": "John Doe"},
					{"id": "2", "name": "Jane Smith"},
				},
			})
		})

		// Permission-based endpoint
		protected.POST("/documents", func(c *gin.Context) {
			if !middleware.HasPermission(c, "write") {
				c.JSON(http.StatusForbidden, gin.H{
					"success": false,
					"message": "Write permission required",
				})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "Document created successfully",
			})
		})

		// Multiple roles endpoint
		protected.GET("/reports", func(c *gin.Context) {
			if !middleware.HasAnyRole(c, "admin", "manager", "analyst") {
				c.JSON(http.StatusForbidden, gin.H{
					"success": false,
					"message": "Admin, manager, or analyst role required",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"reports": []gin.H{
					{"id": "1", "title": "Monthly Report"},
					{"id": "2", "title": "Quarterly Report"},
				},
			})
		})

		// Multiple permissions endpoint
		protected.DELETE("/documents/:id", func(c *gin.Context) {
			if !middleware.HasAllPermissions(c, "write", "delete") {
				c.JSON(http.StatusForbidden, gin.H{
					"success": false,
					"message": "Both write and delete permissions required",
				})
				return
			}

			documentID := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"message": "Document " + documentID + " deleted successfully",
			})
		})
	}

	// Start server
	log.Printf("Starting server on port %d", cfg.Server.Port)
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}