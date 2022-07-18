package main

type Config struct {
	Port                   int    `default:"8081"`
	JWTSecret              []byte `envconfig:"JWT_SECRET" required:"true"`
	DatabaseUri            string `envconfig:"DATABASE_URI" required:"true"`
	LndHubUrl              string `envconfig:"LNDHUB_URL" required:"true"`
	TargetFile             string `envconfig:"TARGET_FILE" default:"targets.json"`
	SentryDSN              string `envconfig:"SENTRY_DSN"`
	AccessTokenExpSeconds  int    `default:"7200"`    //default 2 hours
	RefreshTokenExpSeconds int    `default:"2592000"` //default 30 days
}
