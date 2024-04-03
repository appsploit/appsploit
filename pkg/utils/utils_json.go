package utils

import (
	jsoniter "github.com/json-iterator/go"
	"io"
)

type utilsJson struct{}

func (u *utilsJson) Valid(data []byte) bool {
	return jsoniter.Valid(data)
}

func (u *utilsJson) Get(data []byte, path ...interface{}) jsoniter.Any {
	return jsoniter.Get(data, path...)
}

func (u *utilsJson) Marshal(v interface{}) ([]byte, error) {
	return jsoniter.Marshal(v)
}

func (u *utilsJson) MarshalToString(v interface{}) (string, error) {
	return jsoniter.MarshalToString(v)
}

func (u *utilsJson) Unmarshal(data []byte, v interface{}) error {
	return jsoniter.Unmarshal(data, v)
}

func (u *utilsJson) UnmarshalFromString(str string, v interface{}) error {
	return jsoniter.UnmarshalFromString(str, v)
}

func (u *utilsJson) NewDecoder(reader io.Reader) *jsoniter.Decoder {
	return jsoniter.NewDecoder(reader)
}

func (u *utilsJson) NewEncoder(writer io.Writer) *jsoniter.Encoder {
	return jsoniter.NewEncoder(writer)
}
