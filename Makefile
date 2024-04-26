DC					= docker compose

.PHONY: help
help: ## Help
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' Makefile | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

.PHONY: up
up: ## Start containers (without esb*)
	@$(DC) up -d

.PHONY: down
down: ## Stop and remove containers
	@$(DC) down

.PHONY: init
init: ## Init application (up, cache-remove, logs-remove, var-chmod)
	@$(MAKE) up
	## TODO
