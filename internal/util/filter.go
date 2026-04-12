package util

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type FilterMap map[string]FilterItem

type FilterItem struct {
	Value    any
	Operator string `enum:"lt,gt,eq,ge,le,ne,like,ilike"`
}

type IntoQuery interface {
	ToQuery() string
}

type Filter struct {
	Filters FilterMap
	Sorts   []string
	Offset  uint32
	Limit   uint32
}

// Helper privado para garantir que o mapa existe
func (ff *Filter) initMap() {
	if ff.Filters == nil {
		ff.Filters = make(FilterMap)
	}
}

func (ff *Filter) GetLimit(params url.Values) error {
	if params.Get("limit") != "" {
		if l, err := strconv.ParseUint(params.Get("limit"), 10, 32); err == nil {
			ff.Limit = uint32(l)
		} else {
			return errors.New("Invalid query param `limit`")
		}
	}
	return nil
}

func (ff *Filter) GetOffset(params url.Values) error {
	if params.Get("offset") != "" {
		if o, err := strconv.ParseUint(params.Get("offset"), 10, 32); err == nil {
			ff.Offset = uint32(o)
		} else {
			return errors.New("Invalid query param `offset`")
		}
	}
	return nil
}

func (ff *Filter) GetSorts(params url.Values, attrs []string) error {
	attrStr := strings.Join(attrs, "|")
	regex := fmt.Sprintf("^[-]?(%s)$", attrStr)
	if params.Get("sort") != "" {
		for value := range strings.SplitSeq(params.Get("sort"), ",") {
			if ok, err := regexp.MatchString(regex, value); err == nil && ok {
				ff.Sorts = append(ff.Sorts, value)
			} else {
				return errors.New("Invalid query value for param `sort`")
			}
		}
	}
	return nil
}

func (ff *Filter) GetFilterStr(params url.Values, key string) error {
	ff.initMap() // <--- CORREÇÃO (usando helper)
	filterKey := fmt.Sprintf("filter-%s", key)

	if params.Get(filterKey) != "" {
		parts := strings.Split(params.Get(filterKey), ".")
		if len(parts) != 2 {
			return errors.New("Invalid query param `filter[nome]`")
		}
		if !IsOperatorForStr(parts[0]) {
			return errors.New("Invalid operator for query param `filter[nome]`")
		}
		ff.Filters[key] = FilterItem{
			Operator: parts[0],
			Value:    parts[1],
		}
	}
	return nil
}

func (ff *Filter) GetFilterInt(params url.Values, key string) error {
	ff.initMap() // <--- CORREÇÃO CRÍTICA AQUI
	filterKey := fmt.Sprintf("filter-%s", key)

	if params.Get(filterKey) != "" {
		parts := strings.Split(params.Get(filterKey), ".")
		if len(parts) != 2 {
			return errors.New("Invalid query param `filter[nome]`")
		}
		if !IsOperatorForNumber(parts[0]) {
			return errors.New("Invalid operator for query param `filter[nome]`")
		}

		v, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}
		ff.Filters[key] = FilterItem{
			Operator: parts[0],
			Value:    v,
		}
	}
	return nil
}

func (ff *Filter) GetFilterFloat(params url.Values, key string) error {
	ff.initMap() // <--- CORREÇÃO CRÍTICA AQUI
	filterKey := fmt.Sprintf("filter-%s", key)

	if params.Get(filterKey) != "" {
		parts := strings.Split(params.Get(filterKey), ".")
		if len(parts) != 2 {
			return errors.New("Invalid query param `filter[nome]`")
		}
		if !IsOperatorForNumber(parts[0]) {
			return errors.New("Invalid operator for query param `filter[nome]`")
		}

		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return err
		}
		ff.Filters[key] = FilterItem{
			Operator: parts[0],
			Value:    v,
		}
	}
	return nil
}

func (ff *Filter) GetFilterTime(params url.Values, key string) error {
	ff.initMap() // <--- CORREÇÃO CRÍTICA AQUI
	filterKey := fmt.Sprintf("filter-%s", key)

	if params.Get(filterKey) != "" {
		parts := strings.Split(params.Get(filterKey), ".")
		if len(parts) != 2 {
			return errors.New(fmt.Sprintf("Invalid query param `%s`", filterKey))
		}
		if !IsOperatorForNumber(parts[0]) {
			return errors.New(fmt.Sprintf("Invalid operator for query `%s`", filterKey))
		}

		v, err := time.Parse("2006-01-02 15:04:05", parts[1])
		if err != nil {
			return err
		}
		ff.Filters[key] = FilterItem{
			Operator: parts[0],
			Value:    v,
		}
	}
	return nil
}

// Cria uma sql query apartir de Filter e adiciona valores para preencher a query em values
func (ff *Filter) ToQuery(values *[]any, tableAlias string) string {
	// condições
	var query string
	i := 0
	for k, v := range ff.Filters {
		if i == 0 {
			query += " WHERE"
		} else {
			query += " AND"
		}
		switch v.Operator {
		case "lt":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s < $%d", tableAlias, k, len(*values))
		case "gt":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s > $%d", tableAlias, k, len(*values))
		case "eq":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s = $%d", tableAlias, k, len(*values))
		case "le":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s <= $%d", tableAlias, k, len(*values))
		case "ge":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s >= $%d", tableAlias, k, len(*values))
		case "ne":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s != $%d", tableAlias, k, len(*values))
		case "like":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s LIKE '%%' || $%d || '%%'", tableAlias, k, len(*values))
		case "ilike":
			*values = append(*values, v.Value)
			query += fmt.Sprintf(" %s.%s ILIKE '%%' || $%d || '%%'", tableAlias, k, len(*values))
		default:
			return ""
		}
		i += 1
	}

	// ordenação
	for i, v := range ff.Sorts {
		if i == 0 {
			query += " ORDER BY"
		} else {
			query += ","
		}

		str, fminus := strings.CutPrefix(v, "-")
		query += " " + str
		if fminus {
			query += " DESC"
		}
	}

	// paginação
	if ff.Offset > 0 {
		*values = append(*values, ff.Offset)
		query += " OFFSET $" + strconv.Itoa(len(*values))
	}
	if ff.Limit > 0 {
		*values = append(*values, ff.Limit)
		query += " LIMIT $" + strconv.Itoa(len(*values))
	}
	return query
}

func IsOperatorForStr(op string) bool {
	if op != "like" && op != "ilike" && op != "eq" && op != "ne" {
		return false
	}
	return true
}

func IsOperatorForNumber(op string) bool {
	if op != "eq" && op != "ne" && op != "lt" && op != "gt" && op != "le" && op != "ge" {
		return false
	}
	return true
}
