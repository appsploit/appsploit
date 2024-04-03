package utils

import (
	"crypto/rand"
	"math/big"
	"os"
	"sort"
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
