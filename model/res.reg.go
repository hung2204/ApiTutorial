package model

type RegisterResponse struct {
	Token  string `json:"token"`
	Enc    interface{} `json:"encrypt"`
	Dec    interface{} `json:"decrypt"`
	Status int    `json:"status"`
}
