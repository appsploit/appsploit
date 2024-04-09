package cache

type RespCache struct {
	Header     string
	BodyString string
	BodyBytes  []byte
	BodyHash   []string
}
