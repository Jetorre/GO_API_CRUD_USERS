package models

type Answer struct {
	Message string `db:"error" json:"message"`
	Id      int    `db:"error" json:"id"`
	Status  string `db:"error" json:"status"`
}
