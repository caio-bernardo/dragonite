package util

import (
	"context"
	"database/sql"
)


func QueryRowsWithFilter(db *sql.DB, ctx context.Context, query string, filter *Filter, tableAlias string) (*sql.Rows, error) {
	var filterValues []any
	query += filter.ToQuery(&filterValues, tableAlias)
	// fmt.Println(query)
	return db.QueryContext(ctx, query, filterValues...)
}
