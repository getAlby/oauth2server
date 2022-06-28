package main

type Config struct {
	Port        int    `default:"8081"`
	JWTSecret   []byte `required:"true"`
	DatabaseUri string `envconfig:"DATABASE_URI" required:"true"`
}
