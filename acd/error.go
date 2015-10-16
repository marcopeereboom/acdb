package acd

import "encoding/json"

type CombinedError struct {
	StatusCode int
	Status     string
	Body       []byte
	ErrorJSON  *ResponseError
}

func NewCombinedError(sc int, status string, body []byte) CombinedError {
	c := CombinedError{
		StatusCode: sc,
		Status:     status,
		Body:       body,
	}

	var ej ResponseError
	err := json.Unmarshal(body, &ej)
	if err == nil {
		c.ErrorJSON = &ej
	}

	return c
}

func (c CombinedError) Error() string {
	return c.Status
}

func IsCombinedError(err error) (*CombinedError, bool) {
	ce, ok := err.(CombinedError)
	return &ce, ok
}
