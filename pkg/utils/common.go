package utils

import (
	"appsploit/pkg/dto/hash"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

type utilsCommon struct{}

func (u *utilsCommon) GetEnvDefault(key string, defaultValue string) string {
	if envValue, exist := os.LookupEnv(key); exist {
		return envValue
	}
	return defaultValue
}

func (u *utilsCommon) StringInArray(target string, strArray []string) bool {
	sort.Strings(strArray)
	index := sort.SearchStrings(strArray, target)
	if index < len(strArray) && strArray[index] == target {
		return true
	}
	return false
}

func (u *utilsCommon) RandKey(keyLen int) string {
	characters := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-="
	charsetLength := len(characters)
	key := make([]byte, keyLen)
	for i := range key {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			panic(err)
		}
		key[i] = characters[randomIndex.Int64()]
	}
	return string(key)
}

func (u *utilsCommon) StringRegexpMatch(regexpStr string, dataStr string) (bool, error) {
	match, err := regexp.MatchString(regexpStr, dataStr)
	if err != nil {
		return false, err
	}
	return match, error(nil)
}

func (u *utilsCommon) GetStructValue(obj interface{}, fieldName string) interface{} {
	value := reflect.ValueOf(obj)
	field := value.FieldByName(fieldName)
	if field.IsValid() {
		return field.Interface()
	}
	return nil
}

func (u *utilsCommon) DataHash(hashType int, data []byte) (string, error) {
	errorData := error(nil)
	hashResult := ""
	switch hashType {
	case hash.MD5:
		md5Hash := md5.Sum(data)
		hashResult = hex.EncodeToString(md5Hash[:])
	case hash.SHA1:
		sha1Hash := sha1.Sum(data)
		hashResult = hex.EncodeToString(sha1Hash[:])
	case hash.SHA256:
		sha256Hash := sha256.Sum256(data)
		hashResult = hex.EncodeToString(sha256Hash[:])
	default:
		errorData = fmt.Errorf("hash type not support")
	}
	return hashResult, errorData
}

func (u *utilsCommon) EncodeToUnicode(input string) string {
	var sb strings.Builder
	for _, r := range input {
		sb.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return sb.String()
}
