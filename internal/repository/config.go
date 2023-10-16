package repository

type Config struct {
	DatabaseUri             string `envconfig:"DATABASE_URI" required:"true"`
	DatabaseMaxConns        int    `envconfig:"DATABASE_MAX_CONNS" default:"10"`
	DatabaseMaxIdleConns    int    `envconfig:"DATABASE_MAX_IDLE_CONNS" default:"5"`
	DatabaseConnMaxLifetime int    `envconfig:"DATABASE_CONN_MAX_LIFETIME" default:"1800"` // 30 minutes
	DatadogAgentUrl         string `envconfig:"DATADOG_AGENT_URL"`
}
