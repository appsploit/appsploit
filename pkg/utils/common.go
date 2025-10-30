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

	"github.com/urfave/cli/v2"
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

// ParseCustomData 解析 custom-data 参数
// 格式：key1=value1,key2=value2
// 返回：map[string]string
func (u *utilsCommon) ParseCustomData(ctx *cli.Context) map[string]string {
	result := make(map[string]string)
	customData := ctx.String("custom-data")

	if customData == "" {
		return result
	}

	// 按逗号分割
	pairs := strings.Split(customData, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// 按等号分割
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				result[key] = value
			}
		}
	}

	return result
}

// GetCustomValue 获取指定 key 的值，如果不存在则返回默认值
func (u *utilsCommon) GetCustomValue(ctx *cli.Context, key string, defaultValue string) string {
	data := u.ParseCustomData(ctx)
	if value, exists := data[key]; exists {
		return value
	}
	return defaultValue
}
