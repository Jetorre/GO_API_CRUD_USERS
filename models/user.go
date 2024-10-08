package models

type User struct {
	ID       int    `db:"id" json:"id"`
	Name     string `db:"name" json:"name"`
	Surname  string `db:"surname" json:"surname"`
	Email    string `db:"email" json:"email"`
	Phone    string `db:"phone" json:"phone"`
	Position string `db:"position" json:"position"`
	Company  string `db:"company" json:"company"`
	Password string `db:"password" json:"password"`
}
