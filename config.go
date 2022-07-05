package main

type Config struct {
	Port          int    `default:"8081"`
	JWTSecret     []byte `envconfig:"JWT_SECRET" required:"true"`
	DatabaseUri   string `envconfig:"DATABASE_URI" required:"true"`
	LndHubUrl     string `envconfig:"LNDHUB_URL" required:"true"`
	GetalbyComUrl string `envconfig:"GETALBYCOM_URL" required:"true"`
}
