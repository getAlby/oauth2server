package main

type Config struct {
	Port        int    `default:"8081"`
	JWTSecret   []byte `envconfig:"JWT_SECRET" required:"true"`
	DatabaseUri string `envconfig:"DATABASE_URI" required:"true"`
}
