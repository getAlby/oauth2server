package service

type Config struct {
	Port       int    `default:"8081"`
	JWTSecret  []byte `envconfig:"JWT_SECRET" required:"true"`
	TargetFile string `envconfig:"TARGET_FILE" default:"targets.json"`
	SentryDSN  string `envconfig:"SENTRY_DSN"`
}
