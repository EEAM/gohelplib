package errormanagemet 


// This package contains custom error types for common web requests 
import "fmt"

type ErrorAccessTokenInvalid struct {
		Url  string
		Code int 
		Message string 
}

func (eati ErrorAccessTokenInvalid) Error() string {
	return fmt.Sprintf( "invalid access token - url: '%s', response code %d, response '%s'", eati.Url,eati.Code,eati.Message)
}
