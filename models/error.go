package models

type Error struct {
	Error string `db:"error" json:"error"`
}
