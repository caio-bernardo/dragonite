#!/bin/sh

set -e

# Portable migrate wrapper
# - Detects `migrate` binary from PATH or common install locations
# - Allows overriding the migrate binary with MIGRATE_PATH
# - Only requires DB_URL for commands that actually need the DB (up/down/force/goto/drop/version)
#
# Usage:
#   MIGRATE_PATH=/abs/path/to/migrate DB_URL="postgres://..." ./migrate.sh up
#   ./migrate.sh create add_users_table
#
# Note: MIGRATIONS_DIR and MIGRATE_PATH may be exported in your environment.

# Default migrations directory
MIGRATIONS_DIR=${MIGRATIONS_DIR:-"./migrations"}

# Path to the migrate binary resolved at runtime
MIGRATE_CMD=""


DB_URL="postgres://admin:admin123@localhost:5432/dragonite-database?sslmode=disable"

show_help() {
    echo "Usage: $0 [command]"
    echo
    echo "Environment variables:"
    echo "  DB_URL       Database connection string (required for commands that touch the DB)"
    echo "  MIGRATIONS_DIR  Directory containing migration files (default: ./migrations)"
    echo "  MIGRATE_PATH    Optional absolute path to the migrate binary to use"
    echo
    echo "Commands:"
    echo "  create NAME   Create a new migration with the specified name (does NOT need DB_URL)"
    echo "  up [N]        Apply all or N up migrations"
    echo "  down [N]      Apply all or N down migrations"
    echo "  force V       Force migration version to a specific version"
    echo "  goto V        Migrate to a specific version"
    echo "  drop          Drop everything in the database"
    echo "  version       Show current migration version"
    echo
    echo "Examples:"
    echo "  $0 create add_users_table"
    echo "  $0 up"
    echo "  $0 up 1"
    echo "  $0 down"
    echo "  $0 down 1"
    echo "  $0 force 1"
    echo "  $0 goto 5"
    echo
    echo "If $0 cannot find the migrate binary automatically, set MIGRATE_PATH to an absolute path"
    echo "or add the folder that contains migrate to your PATH."
}

ensure_migrations_dir() {
    if [ ! -d "$MIGRATIONS_DIR" ]; then
        mkdir -p "$MIGRATIONS_DIR"
        echo "Created migrations directory: $MIGRATIONS_DIR"
    fi
}

# Only call when a command requires DB_URL
require_db() {
    if [ -z "${DB_URL:-}" ]; then
        echo "Error: DB_URL environment variable not set."
        echo "Please set DB_URL to your database connection string, e.g.:"
        echo "  export DB_URL=\"postgres://user:pass@localhost:5432/dbname?sslmode=disable\""
        exit 1
    fi
}

# Resolve migrate binary in a portable way:
# 1) If MIGRATE_PATH is set and executable, use it
# 2) If `migrate` exists in PATH, use that
# 3) Look in common user-local directories (home/.local/bin, home/go/bin, home/.gobin/bin)
# 4) Look in mise installs directory (used by some installers) and check nested installs (two levels)
# 5) If not found, print actionable instructions
resolve_migrate() {
    # Respect explicit override
    if [ -n "${MIGRATE_PATH:-}" ]; then
        if [ -x "$MIGRATE_PATH" ]; then
            MIGRATE_CMD="$MIGRATE_PATH"
            return 0
        else
            echo "Warning: MIGRATE_PATH is set but not executable: $MIGRATE_PATH"
            echo "Attempting to locate migrate in PATH and common locations..."
        fi
    fi

    # Prefer the command in PATH if available
    if command -v migrate >/dev/null 2>&1; then
        MIGRATE_CMD="$(command -v migrate)"
        return 0
    fi

    # Common per-user install locations
    # Note: $HOME may be empty in some environments; handle defensively.
    HOME_DIR=${HOME:-}
    CANDIDATES=""
    if [ -n "$HOME_DIR" ]; then
        CANDIDATES="$HOME_DIR/.local/bin $HOME_DIR/go/bin $HOME_DIR/.gobin/bin"
        # Check for mise installs layout used in some toolchains
        CANDIDATES="$CANDIDATES $HOME_DIR/.local/share/mise/installs"
    fi

    for d in $CANDIDATES; do
        # If the candidate is a dir, check for migrate inside it
        if [ -d "$d" ] && [ -x "$d/migrate" ]; then
            MIGRATE_CMD="$d/migrate"
            return 0
        fi

        # If the candidate is the mise installs base, try to find any migrate binary under it
        if [ -d "$d" ] && [ "$(basename "$d")" = "installs" ]; then
            # iterate immediate child install directories
            for child in "$d"/*; do
                if [ -x "$child/bin/migrate" ]; then
                    MIGRATE_CMD="$child/bin/migrate"
                    return 0
                fi

                # Also check one level deeper (some installers nest versions or toolchains)
                if [ -d "$child" ]; then
                    for sub in "$child"/*; do
                        if [ -x "$sub/bin/migrate" ]; then
                            MIGRATE_CMD="$sub/bin/migrate"
                            return 0
                        fi
                    done
                fi
            done
        fi
    done

    # Fallback: look for a migrate binary under home recursively but shallow (avoid long searches)
    if [ -n "$HOME_DIR" ] && command -v find >/dev/null 2>&1; then
        # limit depth to 3 to avoid long-running searches
        FOUND=$(find "$HOME_DIR" -maxdepth 3 -type f -name migrate -perm -111 2>/dev/null | head -n 1 || true)
        if [ -n "$FOUND" ]; then
            MIGRATE_CMD="$FOUND"
            return 0
        fi
    fi

    # Not found
    return 1
}

check_migrate() {
    if resolve_migrate; then
        echo "Using migrate: $MIGRATE_CMD"
        return 0
    else
        echo "Error: migrate command not found."
        echo "Please install golang-migrate: https://github.com/golang-migrate/migrate/tree/master/cmd/migrate"
        echo
        echo "You can install it with Go (example):"
        echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
        echo
        echo "Or set MIGRATE_PATH to the absolute path of an existing migrate binary, e.g.:"
        echo "  export MIGRATE_PATH=\"/home/user/go/bin/migrate\""
        echo
        echo "If you installed migrate to a custom location, add that location to your PATH or set MIGRATE_PATH."
        exit 1
    fi
}

main() {
    # Resolve migrate first so we can show helpful errors early.
    check_migrate

    ensure_migrations_dir

    case "$1" in
        create)
            if [ -z "$2" ]; then
                echo "Error: Migration name required"
                show_help
                exit 1
            fi
            # create does not require DB_URL
            "$MIGRATE_CMD" create -ext sql -dir "$MIGRATIONS_DIR" -seq "$2"
            echo "Created migration files in $MIGRATIONS_DIR"
            ;;
        up)
            require_db
            if [ -z "$2" ]; then
                "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" up
            else
                "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" up "$2"
            fi
            echo "Migration(s) applied"
            ;;
        down)
            require_db
            if [ -z "$2" ]; then
                "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" down
            else
                "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" down "$2"
            fi
            echo "Migration(s) rolled back"
            ;;
        force)
            require_db
            if [ -z "$2" ]; then
                echo "Error: Version number required"
                show_help
                exit 1
            fi
            "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" force "$2"
            echo "Forced migration version to $2"
            ;;
        goto)
            require_db
            if [ -z "$2" ]; then
                echo "Error: Version number required"
                show_help
                exit 1
            fi
            "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" goto "$2"
            echo "Migrated to version $2"
            ;;
        drop)
            require_db
            "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" drop
            echo "Database dropped"
            ;;
        version)
            require_db
            "$MIGRATE_CMD" -path "$MIGRATIONS_DIR" -database "$DB_URL" version
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Error: Unknown command '$1'"
            show_help
            exit 1
            ;;
    esac
}

# Ensure at least one argument (except when no args -> show help)
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

main "$@"
