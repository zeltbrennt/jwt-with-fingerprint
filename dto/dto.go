package dto

type LoginDto struct {
	Username string `json:"user"`
	Password string `json:"password"`
}

func (l *LoginDto) IsValid() bool {
	return l.Username == "admin" && l.Password == "password"
}

type TokenDto struct {
	Token string `json:"token"`
}

type SecretDto struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
